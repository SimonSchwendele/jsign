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

package net.jsign.verify;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.io.TeeOutputStream;

import net.jsign.DigestAlgorithm;

/**
 * Content verifier for Authenticode signatures. Authenticode supports an old
 * non-standard signature format where the encrypted digest is directly wrapped
 * in a PKCS#1 v1.5 padding block without a DigestInfo structure. This content
 * verifier supports both formats; for RSA signatures it first attempts to
 * verify the signature using the standard format, and if that fails it
 * verifies the signature using the raw digest format.
 *
 * @since 8.0
 */
class AuthenticodeContentVerifierProviderBuilder {

    public ContentVerifierProvider build(X509CertificateHolder certificate) throws OperatorCreationException, CertificateException {
        ContentVerifierProvider defaultContentVerifierProvider = new JcaContentVerifierProviderBuilder().build(certificate);
        PublicKey publicKey = new JcaX509CertificateConverter().getCertificate(certificate).getPublicKey();

        return new ContentVerifierProvider() {
            @Override
            public boolean hasAssociatedCertificate() {
                return defaultContentVerifierProvider.hasAssociatedCertificate();
            }

            @Override
            public X509CertificateHolder getAssociatedCertificate() {
                return defaultContentVerifierProvider.getAssociatedCertificate();
            }

            @Override
            public ContentVerifier get(AlgorithmIdentifier algorithm) throws OperatorCreationException {
                ContentVerifier contentVerifier = defaultContentVerifierProvider.get(algorithm);
                if (isRSA(algorithm)) {
                    return new AuthenticodeContentVerifier(algorithm, publicKey, contentVerifier);
                } else {
                    return contentVerifier;
                }
            }

            private boolean isRSA(AlgorithmIdentifier algorithm) {
                ASN1ObjectIdentifier oid = algorithm.getAlgorithm();
                return PKCSObjectIdentifiers.md5WithRSAEncryption.equals(oid)
                        || PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(oid)
                        || PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(oid)
                        || PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(oid)
                        || PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(oid);
            }
        };
    }

    private static class AuthenticodeContentVerifier implements ContentVerifier {

        private final AlgorithmIdentifier signatureAlgorithm;
        private final PublicKey publicKey;
        private final ContentVerifier defaultVerifier;
        private final ByteArrayOutputStream data = new ByteArrayOutputStream();
        private final OutputStream outputStream;

        AuthenticodeContentVerifier(AlgorithmIdentifier signatureAlgorithm, PublicKey publicKey, ContentVerifier defaultVerifier) {
            this.signatureAlgorithm = signatureAlgorithm;
            this.defaultVerifier = defaultVerifier;
            this.publicKey = publicKey;

            this.outputStream = new TeeOutputStream(data, defaultVerifier.getOutputStream());
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return signatureAlgorithm;
        }

        @Override
        public OutputStream getOutputStream() {
            return outputStream;
        }

        @Override
        public boolean verify(byte[] signature) {
            if (defaultVerifier.verify(signature)) {
                return true;
            } else {
                try {
                    return Arrays.equals(calculateDigest(), decrypt(signature)  );
                } catch (GeneralSecurityException e) {
                    return false;
                }
            }
        }

        private byte[] decrypt(byte[] encrypted) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return cipher.doFinal(encrypted);
        }

        private byte[] calculateDigest() {
            AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm);
            return DigestAlgorithm.of(digestAlgorithm.getAlgorithm()).getMessageDigest().digest(data.toByteArray());
        }
    }
}
