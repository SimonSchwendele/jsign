/*
 * Copyright 2026 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.jca;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

@RunWith(Theories.class)
public class RESTClientTest {

    @DataPoints("retryableStatus") // Statuscodes in RESTClient.isRetryableError whose requests are retried a certain number of times
    public static int[] retryableStatus = { 429, 500, 502, 503, 504 };

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    @Test
    public void testRetryOnTimeout() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(200)
                .withDelay(1000, TimeUnit.MILLISECONDS);

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.readTimeout(200);
        client.retries(3);
        client.retryWait(100);

        Exception e = assertThrows(SocketTimeoutException.class, () -> client.get("/test"));
        assertEquals("message", "Unable to connect to http://localhost:" + port() + "/test after 3 attempts", e.getMessage());
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(3);
    }

    @Test
    public void testRetryAndSucceed() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(200)
                .withDelay(500, TimeUnit.MILLISECONDS)
                .thenRespond()
                .withStatus(200)
                .withDelay(500, TimeUnit.MILLISECONDS)
                .thenRespond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"ok\"}");

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.readTimeout(200);
        client.retries(3);
        client.retryWait(400);

        Map<String, ?> response = client.get("/test");
        assertEquals("ok", response.get("status"));
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(3);
    }

    @Test
    public void testNoRetryOnServerError() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(404);

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.retries(3);
        client.retryWait(10);

        Exception e = assertThrows(IOException.class, () -> client.get("/test"));
        assertEquals("message", "HTTP Error 404 - Not Found (http://localhost:" + port() + "/test)", e.getMessage());
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(1);
    }

    @Theory
    public void testRetryOnRetryableResponseSucceeds(@FromDataPoints("retryableStatus") int statusCode) throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(statusCode)
                .thenRespond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"ok\"}");

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.retries(3);
        client.retryWait(10);

        Map<String, ?> response = client.get("/test");
        assertEquals("ok", response.get("status"));
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(2);
    }

    @Test
    public void testRetryableStatusExhausted() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(503);

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.retries(3);
        client.retryWait(10);

        Exception e = assertThrows(IOException.class, () -> client.get("/test"));
        assertEquals("message", "HTTP Error 503 - Service Unavailable (http://localhost:" + port() + "/test)", e.getMessage());
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(3);
    }

    @Test
    public void testNoRetryOnClientError() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(400);

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.retries(3);
        client.retryWait(10);

        assertThrows(IOException.class, () -> client.get("/test"));
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(1);
    }

    @Test
    public void testRetryAfterHeaderInSeconds() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(429)
                .withHeader("Retry-After", "4")
                .thenRespond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"ok\"}");

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.retries(3);
        client.retryWait(10);

        long elapsed = getAndMeasureElapsedMillis(client);

        assertTrue("Retry handling respects remote's 'Retry-After' header", elapsed >= 4000);
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(2);
    }

    @Test
    public void testExponentialBackoffOnRetry() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(503)
                .thenRespond()
                .withStatus(503)
                .thenRespond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"ok\"}");

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.retries(3);
        client.retryWait(200);

        long elapsed = getAndMeasureElapsedMillis(client);

        assertTrue("retryWait increases exponentially on each attempt (200ms + 400ms)", elapsed >= 600);
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(3);
    }

    @Test
    public void testExponentialBackoffGrowsUntilCap() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(503)
                .thenRespond()
                .withStatus(503)
                .thenRespond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"ok\"}");

        RESTClient client = new RESTClient("http://localhost:" + port());
        client.retries(3);
        client.retryWait(5000);
        client.connectTimeout(100);

        long elapsed = getAndMeasureElapsedMillis(client);

        assertTrue("retryWait may not exceed the connections timeout", elapsed < 1000);
        verifyThatRequest().havingMethodEqualTo("GET").havingPathEqualTo("/test").receivedTimes(3);
    }

    private long getAndMeasureElapsedMillis(RESTClient client) throws IOException {
        long start = System.currentTimeMillis();
        Map<String, ?> response = client.get("/test");
        long elapsed = System.currentTimeMillis() - start;

        assertEquals("ok", response.get("status"));
        return elapsed;
    }
}
