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
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.Assume;
import org.junit.Test;

import static org.junit.Assert.*;

public class CertificateVerifierTest {

    @Test(expected = IllegalArgumentException.class)
    public void testVerifyEmptyChain() throws Exception {
        CertificateVerifier verifier = new CertificateVerifier();
        verifier.verify(new ArrayList<>());
    }

    @Test
    public void testVerifyWithTrustedRootCertificate() throws Exception {
        X509Certificate rootCertificate = CertificateChain.load(new File("target/test-classes/keystores/jsign-root-ca.pem")).getLeaf();
        CertificateChain chain = CertificateChain.load(new File("target/test-classes/keystores/jsign-test-certificate-full-chain.pem"));

        CertificateVerifier verifier = new CertificateVerifier()
                .withTrustedCertificates(Collections.singletonList(rootCertificate));
        verifier.verify(chain.toList());
    }

    @Test
    public void testVerifyWithTrustedIntermediateCertificate() throws Exception {
        X509Certificate intermediateCertificate = CertificateChain.load(new File("target/test-classes/keystores/jsign-code-signing-ca.pem")).getLeaf();
        CertificateChain chain = CertificateChain.load(new File("target/test-classes/keystores/jsign-test-certificate-full-chain.pem"));

        CertificateVerifier verifier = new CertificateVerifier()
                .withTrustedCertificates(Collections.singletonList(intermediateCertificate));
        verifier.verify(chain.toList());
    }
    
    @Test(expected = CertificateException.class)
    public void testVerifyWithoutTrustAnchor() throws Exception {
        CertificateVerifier verifier = new CertificateVerifier();

        CertificateChain chain = CertificateChain.load(new File("src/test/resources/keystores/apache-software-foundation-2025.pem")).complete();
        verifier.verify(chain.toList());
    }

    @Test
    public void testVerifyWithTrustAnchorBeforeExpiration() throws Exception {
        CertificateVerifier verifier = new CertificateVerifier()
                .withTrustedKeys(PublicKeyHash.load(new File("target/classes/windows-trusted-keys.csv")))
                .withDate(new SimpleDateFormat("yyyy-MM-dd").parse("2028-10-04"));

        CertificateChain chain = CertificateChain.load(new File("src/test/resources/keystores/apache-software-foundation-2025.pem")).complete();
        verifier.verify(chain.toList());
    }

    @Test(expected = CertPathBuilderException.class)
    public void testVerifyWithTrustAnchorAfterExpiration() throws Exception {
        CertificateVerifier verifier = new CertificateVerifier()
                .withTrustedKey(new PublicKeyHash("7cd67c248f69d83fc2f9bb01dcb1f7ad67a363d046043796d0984c3a231f6bb0"))
                .withDate(new SimpleDateFormat("yyyy-MM-dd").parse("2028-10-07"));

        CertificateChain chain = CertificateChain.load(new File("src/test/resources/keystores/apache-software-foundation-2025.pem")).complete();
        verifier.verify(chain.toList());
    }

    @Test
    public void testVerifyWithRevocationCheck() throws Exception {
        Assume.assumeTrue("Test certificate has expired", LocalDate.now().isBefore(LocalDate.parse("2028-10-05")));

        CertificateVerifier verifier = new CertificateVerifier()
                .withTrustedKey(new PublicKeyHash("7cd67c248f69d83fc2f9bb01dcb1f7ad67a363d046043796d0984c3a231f6bb0"))
                .withRevocationCheck(true);

        CertificateChain chain = CertificateChain.load(new File("src/test/resources/keystores/apache-software-foundation-2025.pem")).complete();
        verifier.verify(chain.toList());
    }

    @Test(expected = CertPathBuilderException.class)
    public void testVerifyWithRevocationCheckFailure() throws Exception {
        CertificateChain chain = CertificateChain.load(new File("src/test/resources/keystores/badssl-revoked.pem")).complete();

        CertificateVerifier verifier = new CertificateVerifier()
                .withTrustedKey(new PublicKeyHash(chain.toList().get(1)))
                .withDate(new SimpleDateFormat("yyyy-MM-dd").parse("2022-10-25"))
                .withRevocationCheck(true);
        verifier.verify(chain.toList());
    }

    @Test
    public void testVerifyMissingCodeSigningKeyUsage() throws Exception {
        CertificateChain chain = CertificateChain.load(new File("target/test-classes/keystores/badssl-revoked.pem"));

        CertificateVerifier verifier = new CertificateVerifier()
                .withKeyPurposeId(KeyPurposeId.id_kp_codeSigning);

        Exception e = assertThrows(CertificateException.class, () -> verifier.verify(chain.toList()));
        assertEquals("The 'revoked.badssl.com' certificate is not authorized for code signing.", e.getMessage());
    }

    @Test
    public void testVerifyMissingTimestampingKeyUsage() throws Exception {
        CertificateChain chain = CertificateChain.load(new File("target/test-classes/keystores/jsign-test-certificate.pem"));

        CertificateVerifier verifier = new CertificateVerifier()
                .withKeyPurposeId(KeyPurposeId.id_kp_timeStamping);

        Exception e = assertThrows(CertificateException.class, () -> verifier.verify(chain.toList()));
        assertEquals("The 'Jsign Code Signing Test Certificate 2024 (RSA)' certificate is not authorized for time stamping.", e.getMessage());
    }

    @Test
    public void testVerifyMissingUnsupportedKeyUsage() throws Exception {
        CertificateChain chain = CertificateChain.load(new File("target/test-classes/keystores/jsign-test-certificate.pem"));

        CertificateVerifier verifier = new CertificateVerifier()
                .withKeyPurposeId(KeyPurposeId.id_kp_serverAuth);

        Exception e = assertThrows(CertificateException.class, () -> verifier.verify(chain.toList()));
        assertEquals("The 'Jsign Code Signing Test Certificate 2024 (RSA)' certificate is not authorized for key purpose 1.3.6.1.5.5.7.3.1.", e.getMessage());
    }
}
