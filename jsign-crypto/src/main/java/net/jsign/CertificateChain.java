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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * Chain of X.509 certificates.
 *
 * <p>The chain may be incomplete and can be completed by downloading the missing issuer certificates
 * from the URLs specified in the Authority Information Access extension of the certificates.</p>
 *
 * @since 8.0
 */
public class CertificateChain {

    private List<X509Certificate> chain;

    public CertificateChain(Collection<X509Certificate> chain) {
        this.chain = new ArrayList<>(chain);
        this.chain.sort(getChainComparator());
    }

    public CertificateChain(Certificate[] chain) {
        this(Arrays.stream(chain).map(certificate -> (X509Certificate) certificate).collect(Collectors.toList()));
    }

    /**
     * Loads the certificate chain from the specified PKCS#7 file.
     */
    public static CertificateChain load(File file) throws IOException, CertificateException {
        try (FileInputStream in = new FileInputStream(file)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return new CertificateChain((Collection<X509Certificate>) certificateFactory.generateCertificates(in));
        }
    }

    /**
     * Returns a comparator that sorts the certificates in the chain in the order of the certification path,
     * from the end-entity certificate to the root CA.
     */
    private Comparator<X509Certificate> getChainComparator() {
        return Comparator.comparing(X509Certificate::getBasicConstraints)
                .thenComparing(X509Certificate::getNotBefore, Comparator.reverseOrder())
                .thenComparing(X509Certificate::getSubjectX500Principal, Comparator.comparing(X500Principal::getName));
    }

    /**
     * Returns the end-entity certificate of the chain (the first certificate in the list).
     */
    public X509Certificate getLeaf() {
        return chain.get(0);
    }

    /**
     * Returns the certificate chain as an array of certificates. The array is sorted in the order of the certification
     * path, from the end-entity certificate to the root CA.
     */
    public X509Certificate[] toArray() {
        return chain.toArray(new X509Certificate[0]);
    }

    /**
     * Returns the certificate chain as a list of certificates. The list is sorted in the order of the certification
     * path, from the end-entity certificate to the root CA.
     */
    public List<X509Certificate> toList() {
        return new ArrayList<>(chain);
    }

    /**
     * Completes the chain with the missing issuer certificates.
     */
    public CertificateChain complete() {
        // find the orphan certificates in the chain (certificates whose issuer is not present in the chain)
        Set<String> missingIssuerNames = chain.stream().map(c -> c.getIssuerX500Principal().getName())
                .collect(Collectors.toCollection(LinkedHashSet::new));
        for (X509Certificate certificate : chain) {
            missingIssuerNames.remove(certificate.getSubjectX500Principal().getName());
        }
        Set<X509Certificate> orphanCertificates = new HashSet<>();
        for (X509Certificate certificate : chain) {
            if (missingIssuerNames.contains(certificate.getIssuerX500Principal().getName())) {
                orphanCertificates.add(certificate);
            }
        }

        List<X509Certificate> fullChain = new ArrayList<>(chain);
        for (X509Certificate orphanCertificate : orphanCertificates) {
            fullChain.remove(orphanCertificate);
            fullChain.addAll(getCertificateChain(orphanCertificate, 10));
        }
        chain = fullChain;

        return this;
    }

    /**
     * Returns the authority information access extension of the specified certificate.
     */
    private static AuthorityInformationAccess getAuthorityInformationAccess(X509Certificate certificate) {
        byte[] aia = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        return aia != null ? AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(aia).getOctets()) : null;
    }

    /**
     * Returns the issuer certificate URL of the specified certificate (HTTP only).
     */
    static String getIssuerCertificateURL(X509Certificate certificate) {
        AuthorityInformationAccess aia = getAuthorityInformationAccess(certificate);
        if (aia != null) {
            for (AccessDescription access : aia.getAccessDescriptions()) {
                if (X509ObjectIdentifiers.id_ad_caIssuers.equals(access.getAccessMethod())) {
                    String url = access.getAccessLocation().getName().toString();
                    if (url.startsWith("http")) {
                        return access.getAccessLocation().getName().toString();
                    }
                }
            }
        }

        return null;
    }

    /**
     * Returns the issuer certificates of the specified certificate. Multiple issuer certificates may be returned
     * if the certificate is cross-signed.
     */
    private static Collection<X509Certificate> getIssuerCertificates(X509Certificate certificate) throws IOException, CertificateException {
        String certificateURL = getIssuerCertificateURL(certificate);
        if (certificateURL != null) {
            File cacheDirectory = new File(OSUtils.getCacheDirectory("jsign"), "certificates");
            HttpClient cache = new HttpClient(cacheDirectory, 90 * 24 * 3600 * 1000L);
            try (InputStream in = cache.getInputStream(new URL(certificateURL))) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                return (Collection) certificateFactory.generateCertificates(in);
            }
        }

        return Collections.emptyList();
    }

    /**
     * Returns the certificate chain of the specified certificate up to the specified depth.
     */
    private static Collection<X509Certificate> getCertificateChain(X509Certificate certificate, int maxDepth) {
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(certificate);

        if (maxDepth > 0 && !CertificateUtils.isSelfSigned(certificate)) {
            try {
                Collection<X509Certificate> issuers = getIssuerCertificates(certificate);
                for (X509Certificate issuer : issuers) {
                    chain.addAll(getCertificateChain(issuer, maxDepth - 1));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return chain;
    }
}
