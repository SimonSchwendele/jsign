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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Certificate verifier.
 *
 * @since 8.0
 */
public class CertificateVerifier {

    private final Provider provider = new BouncyCastleProvider();

    /** The list of trusted certificate keys, identified by the SHA-256 hash of the public key */
    private Set<PublicKeyHash> trustedKeys = new HashSet<>();

    /** The list of trusted certificates */
    private List<X509Certificate> trustedCertificates = new ArrayList<>();

    /** The store of certificates to build the chain from */
    private CertStore certificateStore;

    /** The purpose of the certificate */
    private KeyPurposeId keyPurposeId;

    /** The date to use for certificate validation (optional) */
    private Date date;

    /** Tells if the revocation status of the certificates should be checked (OCSP/CRL) */
    private boolean checkRevocation;

    public CertificateVerifier() {
    }

    public CertificateVerifier withTrustedKey(PublicKeyHash publicKeyHash) {
        trustedKeys.add(publicKeyHash);
        return this;
    }

    public CertificateVerifier withTrustedKeys(Collection<PublicKeyHash> publicKeyHashes) {
        this.trustedKeys = new HashSet<>(publicKeyHashes);
        return this;
    }

    public CertificateVerifier withTrustedCertificates(List<X509Certificate> additionalTrustedCerts) {
        this.trustedCertificates = additionalTrustedCerts != null ? additionalTrustedCerts : new ArrayList<>();
        return this;
    }

    public CertificateVerifier withCertificateStore(CertStore certificateStore) {
        this.certificateStore = certificateStore;
        return this;
    }

    public CertificateVerifier withKeyPurposeId(KeyPurposeId keyPurposeId) {
        this.keyPurposeId = keyPurposeId;
        return this;
    }

    public CertificateVerifier withDate(Date date) {
        this.date = date;
        return this;
    }

    public CertificateVerifier withRevocationCheck(boolean checkRevocation) {
        if (checkRevocation) {
            Security.setProperty("ocsp.enable", "true");
        }
        this.checkRevocation = checkRevocation;
        return this;
    }

    private Set<TrustAnchor> getTrustAnchors() {
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate cert : trustedCertificates) {
            trustAnchors.add(new TrustAnchor(cert, null));
        }

        return trustAnchors;
    }

    /**
     * Tells if the key of the specified certificate is trusted.
     */
    private boolean isTrustedKey(X509Certificate certificate) {
        return trustedKeys.contains(new PublicKeyHash(certificate));
    }

    private void checkKeyPurpose(X509Certificate certificate) throws CertificateException {
        if (keyPurposeId != null) {
            List<String> eku = certificate.getExtendedKeyUsage();
            if (eku == null || !eku.contains(keyPurposeId.getId())) {
                String purpose;
                if (keyPurposeId.equals(KeyPurposeId.id_kp_codeSigning)) {
                    purpose = "code signing";
                } else if (keyPurposeId.equals(KeyPurposeId.id_kp_timeStamping)) {
                    purpose = "time stamping";
                } else {
                    purpose = "key purpose " + keyPurposeId.getId();
                }
                throw new CertificateException("The '" + getCommonName(certificate) + "' certificate is not authorized for " + purpose + ".");
            }
        }
    }

    public CertPath verify(List<X509Certificate> chain) throws GeneralSecurityException {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("The certificate chain is null or empty.");
        }

        withCertificateStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(chain)));

        return verify(chain.get(0));
    }

    public CertPath verify(X509Certificate certificate) throws GeneralSecurityException {
        checkKeyPurpose(certificate);

        // look for trust anchors in the provided certificate store
        Set<TrustAnchor> trustAnchors = getTrustAnchors();
        if (certificateStore != null) {
            for (X509Certificate cert : (Collection<X509Certificate>) certificateStore.getCertificates(new X509CertSelector())) {
                if (isTrustedKey(cert)) {
                    trustAnchors.add(new TrustAnchor(cert, null));
                }
            }
        }

        if (trustAnchors.isEmpty()) {
            List<X509Certificate> chain = buildChain(certificate);
            if (chain.size() == 1) {
                throw new CertificateException("No trust anchor could be established for the certificate:\n" + getCommonName(certificate));
            } else {
                StringBuilder indentedChain = new StringBuilder();
                for (int i = 0; i < chain.size(); i++) {
                    char[] indentation = new char[2 * i];
                    Arrays.fill(indentation, ' ');
                    indentedChain.append(new String(indentation)).append(getCommonName(chain.get(i))).append("\n");
                }
                throw new CertificateException("No trust anchor could be established for the chain:\n" + indentedChain);
            }
        }

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);

        PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, selector);
        params.addCertStore(certificateStore);
        params.setDate(date);

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", provider);

        if (checkRevocation) {
            PKIXRevocationChecker revChecker = (PKIXRevocationChecker) builder.getRevocationChecker();
            //revChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
            params.addCertPathChecker(revChecker);
            params.setRevocationEnabled(true);
        } else {
            params.setRevocationEnabled(false);
        }

        return builder.build(params).getCertPath();
    }

    private String getCommonName(X509Certificate certificate) {
        X500Name name = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        RDN[] rdns = name.getRDNs(BCStyle.CN);
        if (rdns.length == 0) {
            return certificate.getSubjectX500Principal().getName();
        }
        return rdns[0].getFirst().getValue().toString();
    }

    private List<X509Certificate> buildChain(X509Certificate certificate) throws CertStoreException {
        List<X509Certificate> chain = new ArrayList<>();
        X509Certificate current = certificate;
        chain.add(current);

        while (current != null && !current.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
            X509Certificate issuer = getIssuerCertificate(current);
            if (issuer != null) {
                if (chain.contains(issuer)) {
                    break;
                }
                chain.add(issuer);
            }
            current = issuer;
        }

        return chain;
    }

    private X509Certificate getIssuerCertificate(X509Certificate certificate) throws CertStoreException {
        Collection<?> matches = certificateStore.getCertificates(getIssuerSelector(certificate));
        return !matches.isEmpty() ? (X509Certificate) matches.iterator().next() : null;
    }

    private X509CertSelector getIssuerSelector(X509Certificate certificate) throws CertStoreException {
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(certificate.getIssuerX500Principal());
        ASN1OctetString aki = getAuthorityKeyIdentifier(certificate);
        if (aki != null) {
            try {
                selector.setSubjectKeyIdentifier(aki.getEncoded());
            } catch (IOException e) {
                throw new CertStoreException(e);
            }
        }
        return selector;
    }

    private ASN1OctetString getAuthorityKeyIdentifier(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (extension != null) {
            return AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(extension).getOctets()).getKeyIdentifierObject();
        } else {
            return null;
        }
    }
}
