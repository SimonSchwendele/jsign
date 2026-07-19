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

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Hex;

import net.jsign.asn1.authenticode.CertificateTrustList;
import net.jsign.asn1.authenticode.TrustedSubject;

import static java.nio.charset.StandardCharsets.*;

/**
 * Tool to import the certificates trusted by Microsoft for code signing and timestamping.
 * The tool writes the SHA-256 hash of the Subject Public Key Information (SPKI) of each certificate
 * in the windows-trusted-keys.csv file. This file is used to verify the certificate chains.
 *
 * @since 8.0
 */
public class MicrosoftAuthRootImporter {

    public static void main(String[] args) throws Exception {
        CertificateTrustList certificateTrustList = getWindowsCertificateTrustList();
        List<X509Certificate> certificates = getWindowsTrustedCertificates(certificateTrustList);
        System.err.println("Fetched " + certificates.size() + " certificates");

        File outputFile = new File("src/main/resources/windows-trusted-keys.csv");
        outputFile.getParentFile().mkdirs();
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new BufferedOutputStream(Files.newOutputStream(outputFile.toPath())), UTF_8))) {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            out.print("# Windows trusted root certificates (" + dateFormat.format(certificateTrustList.getCtlThisUpdate().getDate()) + ")\n\n");
            generateTrustedSubjectPublicKeyHashFile(certificates, out);
        }
    }

    private static void generateTrustedSubjectPublicKeyHashFile(List<X509Certificate> certificates, PrintWriter out) {
        certificates.sort(Comparator.comparing(t -> t.getSubjectX500Principal().toString()));
        for (X509Certificate certificate : certificates) {
            out.print(new PublicKeyHash(certificate) + "\t" + certificate.getSubjectX500Principal() + "\n");
        }
    }

    /**
     * Fetches all the certificates trusted by Windows.
     */
    private static List<X509Certificate> getWindowsTrustedCertificates(CertificateTrustList certificateTrustList) throws IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        List<String> thumbprints = getWindowsCertificatesThumbprints(certificateTrustList);
        System.err.println("Found " + thumbprints.size() + " certificates");

        ExecutorService executor = Executors.newFixedThreadPool(10);

        for (String thumbprint : thumbprints) {
            executor.submit(() -> {
                try {
                    certificates.add(getWindowsTrustedCertificate(thumbprint));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        executor.shutdown();
        try {
            executor.awaitTermination(60, TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        if (certificates.size() != thumbprints.size()) {
            throw new IOException("Only " + certificates.size() + " certificates could be fetched out of " + thumbprints.size());
        }

        return certificates;
    }

    /**
     * Returns the certificate trusted by Windows with the specified thumbprint.
     *
     * @param thumbprint the thumbprint of the certificate to download
     */
    private static X509Certificate getWindowsTrustedCertificate(String thumbprint) throws IOException, CertificateException {
        URL url = new URL("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/" + thumbprint.toUpperCase() + ".crt");
        ByteArrayInputStream in = new ByteArrayInputStream(fetch(url));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }

    /**
     * Returns the thumbprints of the certificates authorized for code signing or timestamping from the specified certificate trust list.
     */
    private static List<String> getWindowsCertificatesThumbprints(CertificateTrustList certificateTrustList) {
        List<String> thumbprints = new ArrayList<>();

        for (TrustedSubject trustedSubject : certificateTrustList.getTrustedSubjects()) {
            ExtendedKeyUsage eku = trustedSubject.getEnhancedKeyUsage();
            if (eku == null || eku.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning) || eku.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping)) {
                thumbprints.add(Hex.toHexString(trustedSubject.getSubjectIdentifier()));
            }
        }

        return thumbprints;
    }

    /**
     * Downloads the Windows trusted root certificates list (from http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl)
     */
    private static CertificateTrustList getWindowsCertificateTrustList() throws IOException, CMSException {
        byte[] data = fetch(new URL("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl"));
        ASN1Sequence content = (ASN1Sequence) new CMSSignedData(data).getSignedContent().getContent();
        return new CertificateTrustList(content);
    }

    private static byte[] fetch(URL url) throws IOException {
        System.err.println("Fetching: " + url);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        int responseCode = conn.getResponseCode();
        if (responseCode >= 400) {
            throw new IOException("HTTP " + responseCode + " - " + url);
        }
        try (InputStream in = conn.getInputStream()) {
            return IOUtils.toByteArray(in);
        }
    }
}
