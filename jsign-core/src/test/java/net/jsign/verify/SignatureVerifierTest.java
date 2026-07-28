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

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.junit.Ignore;
import org.junit.Test;

import net.jsign.AuthenticodeSigner;
import net.jsign.DigestAlgorithm;
import net.jsign.KeyStoreBuilder;
import net.jsign.MockSignable;
import net.jsign.Signable;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.timestamp.TimestampingMode;

import static net.jsign.DigestAlgorithm.*;
import static net.jsign.verify.CheckResult.Status.*;
import static org.junit.Assert.*;

public class SignatureVerifierTest {

    private static final String PRIVATE_KEY_PASSWORD = "password";
    private static final String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    private X509Certificate loadCertificate(String filename) throws Exception {
        try (FileInputStream in  = new FileInputStream(filename)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    @Test
    public void testVerifyUnsigned() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");

        try (Signable signable = Signable.of(srcFile)) {

            VerificationResult result = new SignatureVerifier().verify(signable);
            assertFalse("invalid signature", result.isValid());
        }
    }

    @Test
    public void testVerify() throws Exception {
        testSignAndVerify(new File("target/test-classes/wineyes.exe"));
    }

    @Test
    public void testVerifyCatalog() throws Exception {
        testSignAndVerify(new File("target/test-classes/cat/wineyes.cat"));
    }

    @Test
    public void testVerifyCabinet() throws Exception {
        testSignAndVerify(new File("target/test-classes/mscab/sample1.cab"));
    }

    @Test
    public void testVerifyMSI() throws Exception {
        testSignAndVerify(new File("target/test-classes/minimal.msi"));
    }

    @Test
    public void testVerifyAPPX() throws Exception {
        testSignAndVerify(new File("target/test-classes/minimal.appxbundle"));
    }

    @Test
    public void testVerifyMSIX() throws Exception {
        testSignAndVerify(new File("target/test-classes/minimal.msix"));
    }

    @Test
    public void testVerifyNAVX() throws Exception {
        testSignAndVerify(new File("target/test-classes/minimal.navx"));
    }

    @Test
    public void testVerifyVBS() throws Exception {
        testSignAndVerify(new File("target/test-classes/hello-world.vbs"));
    }

    @Test
    public void testVerifyJS() throws Exception {
        testSignAndVerify(new File("target/test-classes/hello-world.js"));
    }

    @Test
    public void testVerifyWSF() throws Exception {
        testSignAndVerify(new File("target/test-classes/hello-world.wsf"));
    }

    @Test
    public void testVerifyPowerShell() throws Exception {
        testSignAndVerify(new File("target/test-classes/hello-world.ps1"));
    }

    @Test
    public void testVerifyPowerShellXML() throws Exception {
        testSignAndVerify(new File("target/test-classes/hello-world.ps1xml"));
    }

    @Test
    public void testVerifyNuget() throws Exception {
        testSignAndVerify(new File("target/test-classes/nuget/minimal.1.0.0.nupkg"));
    }

    private void testSignAndVerify(File srcFile) throws Exception {
        File destFile = new File(srcFile.getParentFile(), srcFile.getName().replaceFirst("(\\.[^.]+)$", "-verified$1"));
        FileUtils.copyFile(srcFile, destFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable signable = Signable.of(destFile)) {
            signer.sign(signable);
            testVerify(signable, loadCertificate("target/test-classes/keystores/jsign-root-ca.pem"));
        }
    }

    private void testVerify(Signable signable, X509Certificate... trustedCertificates) throws Exception {
        SignatureVerifier verifier = new SignatureVerifier();
        for (X509Certificate trustedCertificate : trustedCertificates) {
            verifier.addTrustedCertificate(trustedCertificate);
        }
        VerificationResult result = verifier.verify(signable);

        if (!result.isValid()) {
            for (VerificationResult.SignatureVerification verification : result.getSignatureVerifications()) {
                System.out.println("Verification of signature: " + verification.getDigestAlgorithm() + " / " + verification.getCertificate().getSubjectX500Principal());
                for (CheckResult check : verification.getChecks()) {
                    System.out.println(check);
                    if (check.getError() != null) {
                        check.getError().printStackTrace();
                    }
                }
                System.out.println();
            }
        }

        assertTrue("invalid signature", result.isValid());
    }

    @Test
    public void testVerifyUntrustedCertificate() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-verified.exe");
        FileUtils.copyFile(srcFile, destFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable signable = Signable.of(destFile)) {
            signer.sign(signable);

            SignatureVerifier verifier = new SignatureVerifier();
            verifier.addTrustedCertificate(loadCertificate("target/test-classes/keystores/jsign-test-certificate-self-signed.pem"));
            VerificationResult result = verifier.verify(signable);
            assertFalse("Verification should have failed for an untrusted certificate", result.isValid());

            CheckResult checkResult = result.getSignatureVerifications().get(0).getIssues().get(0);
            assertEquals("verification rule", "Certificate Chain Trust", checkResult.getRule());
            assertEquals("verification message", "Certificate chain is not trusted", checkResult.getMessage());
            assertNotNull("verification error is null", checkResult.getError());
            assertEquals("verification error", "Unable to find certificate chain.", checkResult.getError().getMessage());
        }
    }

    @Test
    public void testVerifyExpiredSigningCertificate() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-verified.exe");
        FileUtils.copyFile(srcFile, destFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable signable = Signable.of(destFile)) {
            signer.sign(signable);

            SignatureVerifier verifier = new SignatureVerifier();
            verifier.addTrustedCertificate(loadCertificate("target/test-classes/keystores/jsign-root-ca.pem"));
            verifier.setDate(Date.from(LocalDate.of(2077, 5, 5).atStartOfDay().toInstant(ZoneOffset.UTC)));
            VerificationResult result = verifier.verify(signable);
            assertFalse("Verification should have failed for an expired certificate", result.isValid());

            CheckResult checkResult = result.getSignatureVerifications().get(0).getIssues().get(0);
            assertEquals("verification rule", "Certificate Chain Trust", checkResult.getRule());
            assertEquals("verification message", "Signer certificate is no longer valid on 2077-05-05 (expired on: 2044-05-10)", checkResult.getMessage());
            assertNull("verification error is not null", checkResult.getError());
        }
    }

    @Test
    public void testVerifyNotYetValidSigningCertificate() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-verified.exe");
        FileUtils.copyFile(srcFile, destFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable signable = Signable.of(destFile)) {
            signer.sign(signable);

            SignatureVerifier verifier = new SignatureVerifier();
            verifier.addTrustedCertificate(loadCertificate("target/test-classes/keystores/jsign-root-ca.pem"));
            verifier.setDate(Date.from(LocalDate.of(1977, 5, 5).atStartOfDay().toInstant(ZoneOffset.UTC)));
            VerificationResult result = verifier.verify(signable);
            assertFalse("Verification should have failed for a not yet valid certificate", result.isValid());

            CheckResult checkResult = result.getSignatureVerifications().get(0).getIssues().get(0);
            assertEquals("verification rule", "Certificate Chain Trust", checkResult.getRule());
            assertEquals("verification message", "Signer certificate is not yet valid on 1977-05-05 (valid from: 2024-05-10)", checkResult.getMessage());
            assertNull("verification error is not null", checkResult.getError());
        }
    }

    @Test
    public void testVerifyAlteredFile() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-verified-with-altered-file.exe");
        FileUtils.copyFile(srcFile, destFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable signable = Signable.of(destFile)) {
            signer.sign(signable);
        }

        try (SeekableByteChannel channel = Files.newByteChannel(destFile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(1024);
            channel.write(ByteBuffer.wrap("Jsign".getBytes()));
        }

        try (Signable signable = Signable.of(destFile)) {
            VerificationResult result = new SignatureVerifier().verify(signable);
            assertFalse("Verification should have failed for an altered file", result.isValid());

            CheckResult checkResult = result.getSignatureVerifications().get(0).getIssues().get(0);
            assertEquals("verification rule", "File Integrity", checkResult.getRule());
            assertEquals("verification message", "The file digest does not match the signature", checkResult.getMessage());
            assertEquals("verification expected", "7bb369df020cea757619e1c1d678dbca06b638f2cc45b740b5eacfc21e76b160", checkResult.getExpected());
            assertEquals("verification actual", "b71699e037a74d9d477787f58c476e34739d09503249d9f43396d64ac8044a81", checkResult.getActual());
        }
    }

    @Test
    public void testVerifyCorruptedSignedContent() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-verified-with-corrupted-signed-content.exe");
        FileUtils.copyFile(srcFile, destFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable signable = Signable.of(destFile)) {
            signer.sign(signable);
            
            CMSSignedData signature = signable.getSignatures().get(0);
            signature = modifyContent(signature, "Jsign".getBytes());
            signable.setSignature(signature);

            VerificationResult result = new SignatureVerifier().verify(signable);
            assertFalse("Verification should have failed for a corrupted signed content", result.isValid());
        }
    }

    @Test
    public void testVerifyForgedSignedContent() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-verified-with-forged-signed-content.exe");
        FileUtils.copyFile(srcFile, destFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable signable = Signable.of(destFile)) {
            signer.sign(signable);

            CMSTypedData signedContent = signable.getSignatures().get(0).getSignedContent();
            SpcIndirectDataContent original = SpcIndirectDataContent.parse(ASN1Sequence.getInstance(signedContent.getContent()));
            DigestInfo forgedDigest = new DigestInfo(new AlgorithmIdentifier(SHA1.oid), signable.computeDigest(SHA1));
            SpcIndirectDataContent spcIndirectDataContent = new SpcIndirectDataContent(original.getData(), forgedDigest);
            
            CMSSignedData signature = signable.getSignatures().get(0);
            signature = modifyContent(signature, spcIndirectDataContent.getEncoded());
            signable.setSignature(signature);
            signable.save();
        }

        try (Signable signable = Signable.of(destFile)) {
            SignatureVerifier verifier = new SignatureVerifier();
            verifier.addTrustedCertificate(loadCertificate("target/test-classes/keystores/jsign-root-ca.pem"));
            VerificationResult result = verifier.verify(signable);

            assertFalse("Verification should have failed for a forged signed content", result.isValid());
            assertEquals("number of issues", 1, result.getSignatureVerifications().get(0).getIssues().size());

            CheckResult checkResult = result.getSignatureVerifications().get(0).getIssues().get(0);
            assertEquals("verification ruley", "Signature Integrity", checkResult.getRule());
            assertEquals("verification message", "Signature data is invalid", checkResult.getMessage());
            assertNotNull("missing verification error", checkResult.getError());
            assertEquals("verification error", "message-digest attribute value does not match calculated value", checkResult.getError().getMessage());
        }
    }

    /**
     * Modifies the signed content of a signature.
     */
    public CMSSignedData modifyContent(CMSSignedData signature, byte[] modifiedContent) throws Exception {
        SignedData signedData = SignedData.getInstance(signature.toASN1Structure().getContent());
        SignedData modifiedSignedData = new SignedData(
                signedData.getDigestAlgorithms(),
                new ContentInfo(signedData.getEncapContentInfo().getContentType(), new DEROctetString(modifiedContent)),
                signedData.getCertificates(),
                signedData.getCRLs(),
                signedData.getSignerInfos());

        return new CMSSignedData(new ContentInfo(signature.toASN1Structure().getContentType(), modifiedSignedData));
    }

    @Test
    public void testVerifyRFC3161Timestamp() throws Exception {
        testVerifyTimestamp(TimestampingMode.RFC3161);
    }
    @Test
    public void testVerifyAuthenticodeTimestamp() throws Exception {
        testVerifyTimestamp(TimestampingMode.AUTHENTICODE);
    }

    public void testVerifyTimestamp(TimestampingMode mode) throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-verified-with-" + mode.name().toLowerCase() + "-timestamp.exe");
        FileUtils.copyFile(srcFile, destFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(true)
                .withTimestampingMode(mode);

        try (Signable signable = Signable.of(destFile)) {
            signer.sign(signable);

            SignatureVerifier verifier = new SignatureVerifier();
            verifier.addTrustedCertificate(loadCertificate("target/test-classes/keystores/jsign-root-ca.pem"));
            VerificationResult result = verifier.verify(signable);
            assertTrue("invalid signature", result.isValid());

            CheckResult checkResult = result.getSignatureVerifications().get(0).getChecks().get(1);
            assertEquals("verification rule", "Timestamp", checkResult.getRule());
            assertEquals("verification status", PASSED, checkResult.getStatus());
            assertNull("verification error", checkResult.getError());
        }
    }

    @Test
    public void testVerifyExpiredTimestampCertificate() throws Exception {
        // The timestamp certificate is expired, but the signature is still valid
        testVerifyDetachedSignature("expired-timestamp-certificate.p7s", SHA256, "a3a48cae33a8f803e75e8789e4d0aa656548f00c0b7f109143c24ec2ec345355");
    }

    @Test
    public void testVerifyExternalAuthenticodeTimestamp() throws Exception {
        // The certificates in the signature consist in a mix of signing and timestamping certificates.
        // This test ensures Jsign picks the right certificates for each purpose
        testVerifyDetachedSignature("authenticode-timestamp.p7s", SHA1, "a75c5f46e6404e0a830f1b1ef18cc5444f6725d5");
    }

    @Test
    public void testVerifyAuthenticodeTimestampContentTypeTSTInfo() throws Exception {
        // The content-type of the timestamp is id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4) instead of id-data (1.2.840.113549.1.7.1)
        testVerifyDetachedSignature("authenticode-timestamp-content-type-tstinfo.p7s", SHA256, "724dd6d7ce8b9661a44dd4304c37d98e5223fb62d558533f81e2147d35d06d7d");
    }

    @Test
    public void testVerifyAuthenticodeTimestampRawDigest() throws Exception {
        // The signed content of the timestamp is the raw MD5 digest of the signature with the PKCS#1 v1.5 padding,
        // instead of the digest wrapped in a DigestInfo structure. This signature also features a root timestamping
        // certificate that is not downloadable through an AIA link.
        testVerifyDetachedSignature("authenticode-timestamp-raw-digest.p7s", SHA1, "cef117bfd24f2bad41358e7fd2fe9a8a061d37e9");
    }

    @Test
    @Ignore
    public void testVerifyRFC3161TimestampSignatureError() throws Exception {
        // The timestamp signature in not valid according to Bouncy Castle (it throws an TSPValidationException
        // "signature not created by certificate", because the actual digest doesn't match the decrypted value)
        // but Windows considers it valid. This signature comes from Acrobat Reader
        // (C:\Program Files\Adobe\Acrobat DC\Acrobat\RDCNotificationClient\RDCNotificationClient.appx)
        testVerifyDetachedSignature("rfc3161-timestamp-signature-error.p7s", SHA256,
                "41505058" + // APPX
                "41585043" + // AXPC
                "776877fef011e82dc6b1c60dc665a6bda6b2156ed0b4171298948108bea63a97" +
                "41584344" + // AXCD
                "beea91ebb070800588bf1d0a3bfe2ff67c37c24c9fd8175852a6916bc06f5081" +
                "41584354" + // AXCT
                "e0e9f4462f5ba2695d196d7c9f0b14d9ef0809ec68835c78ff0a5ab8ea93e7d0" +
                "4158424d" + // AXBM
                "1a7ce307df343640298e2661120b8dec719ab74d534af98c6aabddd4b1dd4cb3" +
                "41584349" + // AXCI
                "cd9a896cd3f363664f5597a1d5f8198672172e3b8830bcdba7a75ed6cf92438a");
    }

    @Test
    public void testVerifyRFC3161TimestampNonCriticalEKU() throws Exception {
        // The timestamp token was signed by a certificate with a non-critical Extended Key Usage extension.
        // This is accepted by Windows but deviates from the RFC 3161 specification.
        testVerifyDetachedSignature("rfc3161-timestamp-non-critical-eku.p7s", SHA256, "fee8611e65296862facea47bc8f3732074c98401010ecf4d11a0e0b2c762e1ba");
    }

    @Test
    public void testVerifyLifetimeSigningEKU() throws Exception {
        // The signing certificate has the lifetime-signing EKU, the timestamp must not be checked
        try (MockSignable signable = new MockSignable()) {
            signable.attachSignatures(new File("target/test-classes/signatures/lifetime-signing-eku.p7s"));
            signable.setDigest(SHA256, "d04b881fbbb83f4ab7b13e3dbf6472294216a13e5c624861a6d8a98088e7089c");

            SignatureVerifier verifier = new SignatureVerifier();
            VerificationResult result = verifier.verify(signable);

            assertFalse("valid signature", result.isValid());
            assertEquals("verification rule", "Timestamp", result.getSignatureVerifications().get(0).getChecks().get(1).getRule());
            assertEquals("verification status", SKIPPED, result.getSignatureVerifications().get(0).getChecks().get(1).getStatus());
            assertEquals("verification message", "Certificate has the lifetime signing key purpose, timestamp is ignored", result.getSignatureVerifications().get(0).getChecks().get(1).getMessage());
        }
    }

    private void testVerifyDetachedSignature(String filename, DigestAlgorithm digestAlgorithm, String digest) throws Exception {
        try (MockSignable signable = new MockSignable()) {
            signable.attachSignatures(new File("target/test-classes/signatures/" + filename));
            signable.setDigest(digestAlgorithm, digest);

            testVerify(signable);
        }
    }
}
