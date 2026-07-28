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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.function.Supplier;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;

import net.jsign.CertificateChain;
import net.jsign.CertificateVerifier;
import net.jsign.PublicKeyHash;

import static net.jsign.verify.CheckResult.Status.*;

/**
 * Verification rule checking if the signer certificate chain is trusted.
 *
 * @since 8.0
 */
class CertificateChainTrustRule extends VerificationRule {

    /** The list of trusted certificates */
    private List<X509Certificate> trustedCertificates = new ArrayList<>();

    public CertificateChainTrustRule withTrustedCertificates(List<X509Certificate> trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
        return this;
    }

    @Override
    public CheckResult check(VerificationContext context) throws IOException {
        try {
            CertificateChain chain = CertificateChain.build(context.getSignerCertificate(), new JcaCertStoreBuilder().addCertificates(context.getSignature().getCertificates()).build()).complete();
            CertStore completedStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(chain.toList()));

            Supplier<DateFormat> fmt = () -> {
                SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd");
                f.setTimeZone(TimeZone.getTimeZone("UTC"));
                return f;
            };

            Date notAfter = context.getSignerCertificate().getNotAfter();
            if (context.getDate().after(notAfter)) {
                return new CheckResult(getName(), FAILED, "Signer certificate is no longer valid on " + fmt.get().format(context.getDate()) + " (expired on: " + fmt.get().format(notAfter) + ")");
            }
            Date notBefore = context.getSignerCertificate().getNotBefore();
            if (context.getDate().before(notBefore)) {
                return new CheckResult(getName(), FAILED, "Signer certificate is not yet valid on " + fmt.get().format(context.getDate()) + " (valid from: " + fmt.get().format(notBefore) + ")");
            }

            CertificateVerifier verifier = new CertificateVerifier()
                    .withKeyPurposeId(KeyPurposeId.id_kp_codeSigning)
                    .withTrustedCertificates(trustedCertificates)
                    .withTrustedKeys(PublicKeyHash.load(getClass().getClassLoader().getResourceAsStream("windows-trusted-keys.csv")))
                    .withCertificateStore(completedStore)
                    .withDate(context.getDate());
            CertPath path = verifier.verify(context.getSignerCertificate());
            context.setCertPath(path);
            return new CheckResult(getName(), PASSED, "Certificate chain is trusted");
        } catch (GeneralSecurityException e) {
            return new CheckResult(getName(), FAILED, "Certificate chain is not trusted", e);
        }
    }
}
