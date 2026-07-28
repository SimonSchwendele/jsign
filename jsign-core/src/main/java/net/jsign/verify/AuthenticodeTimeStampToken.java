/*
 * Copyright 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package net.jsign.verify;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

/**
 * Carrier class for a TimeStampToken.
 *
 * <p>This class is a minimized copy of the org.bouncycastle.tsp.TimeStampToken from Bouncy Castle with a relaxed
 * validation logic allowing TSA certificates with a non-critical ExtendedKeyUsage extension.</p>
 *
 * @since 8.0
 */
class AuthenticodeTimeStampToken {
    CMSSignedData tsToken;

    SignerInformation tsaSignerInfo;

    AuthenticodeTimeStampTokenInfo tstInfo;

    ESSCertIDv2 certID;

    public AuthenticodeTimeStampToken(CMSSignedData signedData) throws TSPException, IOException {
        this.tsToken = signedData;

        if (!this.tsToken.getSignedContentTypeOID().equals(PKCSObjectIdentifiers.id_ct_TSTInfo.getId())) {
            throw new TSPValidationException("ContentInfo object not for a time stamp.");
        }

        Collection<SignerInformation> signers = tsToken.getSignerInfos().getSigners();

        if (signers.size() != 1) {
            throw new IllegalArgumentException("Time-stamp token signed by " + signers.size() + " signers, but it must contain just the TSA signature.");
        }

        tsaSignerInfo = signers.iterator().next();

        try {
            CMSProcessable content = tsToken.getSignedContent();
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            content.write(bOut);

            this.tstInfo = new AuthenticodeTimeStampTokenInfo(TSTInfo.getInstance(bOut.toByteArray()));

            Attribute attr = tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificate);

            if (attr != null) {
                SigningCertificate signCert = SigningCertificate.getInstance(attr.getAttrValues().getObjectAt(0));

                this.certID = ESSCertIDv2.from(ESSCertID.getInstance(signCert.getCerts()[0]));
            } else {
                attr = tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);

                if (attr == null) {
                    throw new TSPValidationException("no signing certificate attribute found, time stamp invalid.");
                }

                SigningCertificateV2 signCertV2 = SigningCertificateV2.getInstance(attr.getAttrValues().getObjectAt(0));

                this.certID = ESSCertIDv2.getInstance(signCertV2.getCerts()[0]);
            }
        } catch (CMSException e) {
            throw new TSPException(e.getMessage(), e.getUnderlyingException());
        }
    }

    public AuthenticodeTimeStampTokenInfo getTimeStampInfo() {
        return tstInfo;
    }

    public SignerId getSID() {
        return tsaSignerInfo.getSID();
    }

    public Store<X509CertificateHolder> getCertificates() {
        return tsToken.getCertificates();
    }

    /**
     * Validate the time stamp token.
     *
     * <p>To be valid the token must be signed by the passed in certificate and
     * the certificate must be the one referred to by the SigningCertificate
     * attribute included in the hashed attributes of the token. The
     * certificate must also have the ExtendedKeyUsageExtension with only
     * KeyPurposeId.id_kp_timeStamping and have been valid at the time the
     * timestamp was created.</p>
     *
     * <p>A successful call to validate means all the above are true.</p>
     *
     * @param sigVerifier the content verifier create the objects required to verify the CMS object in the timestamp.
     * @throws TSPException             if an exception occurs in processing the token.
     * @throws TSPValidationException   if the certificate or signature fail to be valid.
     * @throws IllegalArgumentException if the sigVerifierProvider has no associated certificate.
     */
    public void validate(SignerInformationVerifier sigVerifier) throws TSPException, TSPValidationException {
        if (!sigVerifier.hasAssociatedCertificate()) {
            throw new IllegalArgumentException("verifier provider needs an associated certificate");
        }

        try {
            X509CertificateHolder certHolder = sigVerifier.getAssociatedCertificate();
            DigestCalculator calc = sigVerifier.getDigestCalculator(certID.getHashAlgorithm());

            OutputStream cOut = calc.getOutputStream();
            cOut.write(certHolder.getEncoded());
            cOut.close();

            if (!Arrays.constantTimeAreEqual(certID.getCertHashObject().getOctets(), calc.getDigest())) {
                throw new TSPValidationException("certificate hash does not match certID hash.");
            }

            IssuerSerial issuerSerial = certID.getIssuerSerial();
            if (issuerSerial != null) {
                Certificate c = certHolder.toASN1Structure();

                if (!issuerSerial.getSerial().equals(c.getSerialNumber())) {
                    throw new TSPValidationException("certificate serial number does not match certID for signature.");
                }

                GeneralName[] names = issuerSerial.getIssuer().getNames();
                boolean found = false;

                for (int i = 0; i != names.length; i++) {
                    if (names[i].getTagNo() == GeneralName.directoryName && X500Name.getInstance(names[i].getName()).equals(c.getIssuer())) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    throw new TSPValidationException("certificate name does not match certID for signature. ");
                }
            }

            validateCertificate(certHolder);

            if (!certHolder.isValidOn(tstInfo.getGenTime())) {
                throw new TSPValidationException("certificate not valid when time stamp created.");
            }

            if (!tsaSignerInfo.verify(sigVerifier)) {
                throw new TSPValidationException("signature not created by certificate.");
            }
        } catch (CMSException e) {
            if (e.getUnderlyingException() != null) {
                throw new TSPException(e.getMessage(), e.getUnderlyingException());
            } else {
                throw new TSPException("CMS exception: " + e, e);
            }
        } catch (IOException e) {
            throw new TSPException("problem processing certificate: " + e, e);
        } catch (OperatorCreationException e) {
            throw new TSPException("unable to create digest: " + e.getMessage(), e);
        }
    }

    /**
     * Validate the passed in certificate as being of the correct type to be used
     * for time stamping. To be valid it must have an ExtendedKeyUsage extension
     * which has a key purpose identifier of id-kp-timeStamping.
     *
     * <p>This method is a copy of TSPUtil.validateCertificate() allowing
     * TSA certificates with a non-critical ExtendedKeyUsage extension.</p>
     *
     * @param cert the certificate of interest.
     * @throws TSPValidationException if the certificate fails on one of the check points.
     */
    private void validateCertificate(X509CertificateHolder cert) throws TSPValidationException {
        if (cert.toASN1Structure().getVersionNumber() != 3) {
            throw new IllegalArgumentException("Certificate must have an ExtendedKeyUsage extension.");
        }

        Extension ext = cert.getExtension(Extension.extendedKeyUsage);
        if (ext == null) {
            throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension.");
        }

        if (!ext.isCritical()) {
            //throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");
        }

        ExtendedKeyUsage extKey = ExtendedKeyUsage.getInstance(ext.getParsedValue());

        if (!extKey.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping) || extKey.size() != 1) {
            throw new TSPValidationException("ExtendedKeyUsage not solely time stamping.");
        }
    }
}
