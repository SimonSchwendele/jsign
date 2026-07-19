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

package net.jsign;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.junit.Test;

import static org.junit.Assert.*;

public class PublicKeyHashTest {

    @Test
    public void testCreateFromString() {
        PublicKeyHash hash = new PublicKeyHash("7cd67c248f69d83fc2f9bb01dcb1f7ad67a363d046043796d0984c3a231f6bb0");

        assertEquals("hash", "7cd67c248f69d83fc2f9bb01dcb1f7ad67a363d046043796d0984c3a231f6bb0", hash.toString());
    }

    @Test
    public void testCreateFromCertificate() throws Exception {
        X509Certificate certificate = CertificateChain.load(new File("src/test/resources/keystores/jsign-test-certificate.pem")).getLeaf();
        PublicKeyHash hash = new PublicKeyHash(DigestAlgorithm.SHA256.getMessageDigest().digest(certificate.getPublicKey().getEncoded()));

        assertEquals("hash", hash, new PublicKeyHash(certificate));
    }

    @Test
    public void testLoad() throws Exception {
        Set<PublicKeyHash> hashes = PublicKeyHash.load(new File("target/classes/windows-trusted-keys.csv"));

        assertFalse(hashes.isEmpty());
        assertTrue(hashes.contains(new PublicKeyHash("dedb13bcde2375995a1c37bd68a7c4a82af5cbb9c4df821b62d5733009028f07")));
    }
}
