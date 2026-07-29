/*
 * Copyright 2023 Emmanuel Bourg
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
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import static org.junit.Assert.*;

public class CertificateChainTest {

    @Test
    public void testLoad() throws Exception {
        X509Certificate certificate = CertificateChain.load(new File("target/test-classes/keystores/jsign-test-certificate-full-chain.pem")).getLeaf();
        assertEquals("first certificate", "CN=Jsign Code Signing Test Certificate 2024 (RSA)", certificate.getSubjectX500Principal().getName());
    }

    @Test
    public void testLoadReversed() throws Exception {
        X509Certificate certificate = CertificateChain.load(new File("target/test-classes/keystores/jsign-test-certificate-full-chain-reversed.pem")).getLeaf();
        assertEquals("first certificate", "CN=Jsign Code Signing Test Certificate 2024 (RSA)", certificate.getSubjectX500Principal().getName());
    }

    @Test
    public void testGetIssuerCertificateURL() throws Exception {
        X509Certificate[] chain = CertificateChain.load(new File("target/test-classes/keystores/jsign-test-certificate-full-chain.pem")).toArray();

        assertEquals("certificate 1 issuer", "http://raw.githubusercontent.com/ebourg/jsign/master/jsign-core/src/test/resources/keystores/jsign-code-signing-ca.cer", CertificateChain.getIssuerCertificateURL(chain[0]));
        assertEquals("certificate 2 issuer", "http://raw.githubusercontent.com/ebourg/jsign/master/jsign-core/src/test/resources/keystores/jsign-root-ca.cer", CertificateChain.getIssuerCertificateURL(chain[1]));
        assertNull("certificate 3 issuer", CertificateChain.getIssuerCertificateURL(chain[2]));
    }

    @Test
    public void testGetFullCertificateChain() throws Exception {
        System.setProperty("jsign.cachedir", "target/test-classes/cache/");

        CertificateChain chain = CertificateChain.load(new File("target/test-classes/keystores/jsign-test-certificate-full-chain-2026.pem"));
        CertificateChain completedChain = new CertificateChain(Collections.singletonList(chain.getLeaf())).complete();

        List<X509Certificate> fullChain = completedChain.toList();
        assertEquals("chain size", chain.toList().size(), fullChain.size());

        assertEquals("certificate 1", "CN=Jsign Code Signing Test Certificate 2026 (RSA)", fullChain.get(0).getSubjectDN().getName());
        assertEquals("certificate 2", "CN=Jsign Code Signing CA 2024", fullChain.get(1).getSubjectDN().getName());
        assertEquals("certificate 3", "CN=Jsign Root Certificate Authority 2024", fullChain.get(2).getSubjectDN().getName());
    }
}
