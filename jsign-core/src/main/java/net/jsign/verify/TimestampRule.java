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
import java.security.MessageDigest;
import java.security.cert.CertStore;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

import net.jsign.CertificateChain;
import net.jsign.CertificateVerifier;
import net.jsign.PublicKeyHash;

import static net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers.*;
import static net.jsign.verify.CheckResult.Status.*;
import static org.bouncycastle.asn1.cms.CMSAttributes.*;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.*;

/**
 * Verification rules checking if the signature contains a valid timestamp.
 *
 * <p>This rule is skipped if the signing certificate has the lifetime signing EKU.</p>
 *
 * <p>A signature may have multiple timestamps, but Windows takes only one into
 * account:</p>
 * <ul>
 *   <li>An Authenticode timestamp has the priority over a RFC 3161 timestamp.</li>
 *   <li>If the signature contains multiple timestamps of the same type, Windows
 *       picks one with an unknown criteria. It's neither the first nor the last one,
 *       and some timestamping certificates seem to take precedence over others.</li>
 * </ul>
 *
 * <p>This verification rule prioritizes the Authenticode timestamp over the
 * RFC 3161 timestamp, and takes the first of a given type if multiple timestamps
 * are present.</p>
 *
 * @since 8.0
 */
class TimestampRule extends VerificationRule {

    @Override
    public CheckResult check(VerificationContext context) throws IOException {
        // Ignore the timestamp if the certificate has the lifetime signing key purpose
        try {
            List<String> extendedKeyUsage = context.getSignerCertificate().getExtendedKeyUsage();
            if (extendedKeyUsage != null && extendedKeyUsage.contains(OID_KP_LIFETIME_SIGNING.getId())) {
                return new CheckResult(getName(), SKIPPED, "Certificate has the lifetime signing key purpose, timestamp is ignored");
            }
        } catch (CertificateParsingException e) {
            throw new IOException(e);
        }

        SignerInformation signer = context.getSignerInformation();
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

        if (unsignedAttributes != null) {
            // The Authenticode timestamp takes precedence over the RFC 3161 timestamp
            Attribute timestampAttribute = unsignedAttributes.get(counterSignature);
            if (timestampAttribute != null) {
                return verifyAuthenticodeTimestamp(timestampAttribute, context);
            }

            timestampAttribute = unsignedAttributes.get(id_aa_signatureTimeStampToken);
            if (timestampAttribute == null) {
                timestampAttribute = unsignedAttributes.get(SPC_RFC3161_OBJID);
            }
            if (timestampAttribute != null) {
                return verifyRFC3161Timestamp(timestampAttribute, context);
            }
        }

        return new CheckResult(getName(), SKIPPED, "No timestamp found");
    }

    private CheckResult verifyRFC3161Timestamp(Attribute timestampAttribute, VerificationContext context) {
        try {
            CMSSignedData tokenSignedData = new CMSSignedData(ContentInfo.getInstance(timestampAttribute.getAttrValues().getObjectAt(0)));
            AuthenticodeTimeStampToken timestampToken = new AuthenticodeTimeStampToken(tokenSignedData);
            AuthenticodeTimeStampTokenInfo info = timestampToken.getTimeStampInfo();

            ASN1ObjectIdentifier hashAlgOid = info.getHashAlgorithm().getAlgorithm();
            MessageDigest digestEngine = MessageDigest.getInstance(hashAlgOid.getId());
            byte[] expectedDigest = digestEngine.digest(context.getSignerInformation().getSignature());
            byte[] actualDigest = info.getMessageImprintDigest();

            if (!Arrays.equals(expectedDigest, actualDigest)) {
                String expectedHex = Hex.toHexString(expectedDigest);
                String actualHex = Hex.toHexString(actualDigest);
                return new CheckResult(getName(), FAILED, "RFC 3161 timestamp message imprint mismatch", expectedHex, actualHex);
            }

            Collection<X509CertificateHolder> matches = timestampToken.getCertificates().getMatches(timestampToken.getSID());

            if (matches.isEmpty()) {
                return new CheckResult(getName(), FAILED, "RFC 3161 timestamping authority certificate not found in the timestamp token");
            }

            X509CertificateHolder timestampCertificate = matches.iterator().next();

            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().build(timestampCertificate);
            try {
                timestampToken.validate(verifier);
            } catch (TSPException e) {
                return new CheckResult(getName(), FAILED, "RFC 3161 timestamp cryptographic signature is invalid", e);
            }

            try {
                verifyTimestampCertificate(timestampCertificate, timestampToken.getCertificates(), info.getGenTime());
            } catch (GeneralSecurityException e) {
                return new CheckResult(getName(), FAILED, "RFC 3161 timestamp certificate is not trusted", e);
            }

            Date timestampDate = info.getGenTime();
            context.setDate(timestampDate);

            return new CheckResult(getName(), PASSED, "Valid RFC 3161 timestamp (" + timestampDate + ")");

        } catch (Exception e) {
            return new CheckResult(getName(), FAILED, "Invalid RFC 3161 timestamp signature or structure", e);
        }
    }

    private CheckResult verifyAuthenticodeTimestamp(Attribute timestampAttribute, VerificationContext context) {
        try {
            ASN1Encodable attrValue = timestampAttribute.getAttrValues().getObjectAt(0);
            SignerInfo signerInfo = SignerInfo.getInstance(attrValue.toASN1Primitive());
            SignerInformation tsaSigner = createStandaloneSignerInformation(signerInfo, context.getSignerInformation().getSignature());

            Attribute signingTimeAttr = tsaSigner.getSignedAttributes().get(CMSAttributes.signingTime);
            if (signingTimeAttr == null) {
                return new CheckResult(getName(), FAILED, "Authenticode timestamp missing signingTime attribute");
            }

            Time time = Time.getInstance(signingTimeAttr.getAttrValues().getObjectAt(0));
            Date timestampDate = time.getDate();

            Collection<?> matchCerts = context.getSignature().getCertificates().getMatches(tsaSigner.getSID());
            if (matchCerts.isEmpty()) {
                return new CheckResult(getName(), FAILED, "Authenticode timestamping authority certificate not found");
            }

            X509CertificateHolder timestampCertificate = (X509CertificateHolder) matchCerts.iterator().next();

            SignerInformationVerifier verifier = new SignerInformationVerifier(
                    new DefaultCMSSignatureAlgorithmNameGenerator(),
                    new DefaultSignatureAlgorithmIdentifierFinder(),
                    new AuthenticodeContentVerifierProviderBuilder().build(timestampCertificate),
                    new JcaDigestCalculatorProviderBuilder().build());

            if (!tsaSigner.verify(verifier)) {
                return new CheckResult(getName(), FAILED, "Authenticode timestamp cryptographic signature is invalid");
            }

            try {
                verifyTimestampCertificate(timestampCertificate, context.getSignature().getCertificates(), timestampDate);
            } catch (GeneralSecurityException e) {
                return new CheckResult(getName(), FAILED, "Authenticode timestamp certificate is not trusted", e);
            }

            context.setDate(timestampDate);

            return new CheckResult(getName(), PASSED, "Valid Authenticode timestamp (" + timestampDate + ")");

        } catch (Exception e) {
            return new CheckResult(getName(), FAILED, "Invalid Authenticode timestamp structure or signature", e);
        }
    }

    private void verifyTimestampCertificate(X509CertificateHolder certificate, Store<X509CertificateHolder> store, Date date) throws IOException, GeneralSecurityException {
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certificate);
        CertificateChain chain = CertificateChain.build(cert, new JcaCertStoreBuilder().addCertificates(store).build()).complete();
        CertStore completedStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(chain.toList()));

        CertificateVerifier verifier = new CertificateVerifier()
                .withTrustedKeys(PublicKeyHash.load(getClass().getClassLoader().getResourceAsStream("windows-trusted-keys.csv")))
                .withCertificateStore(completedStore)
                .withKeyPurposeId(KeyPurposeId.id_kp_timeStamping)
                .withDate(date);
        verifier.verify(cert);
    }

    /**
     * Transforms the SignerInfo from the counter-signature into a SignerInformation without
     * the counter-signature flag. This is necessary because the authenticode counter-signature
     * contains a signed content-type attribute that prevents Bouncy Castle from verifying it
     * (this attribute is not allowed for counter-signatures according to RFC 3852).
     */
    private SignerInformation createStandaloneSignerInformation(SignerInfo signerInfo, byte[] encryptedDigest) throws Exception {
        ASN1ObjectIdentifier contentType = CMSObjectIdentifiers.data;
        AttributeTable attributes = new AttributeTable(signerInfo.getAuthenticatedAttributes());
        Attribute contentTypeAttribute = attributes.get(CMSAttributes.contentType);
        if (contentTypeAttribute != null && contentTypeAttribute.getAttrValues().size() > 0) {
            contentType = ASN1ObjectIdentifier.getInstance(contentTypeAttribute.getAttrValues().getObjectAt(0));
        }

        ContentInfo encapContentInfo = new ContentInfo(contentType, new DEROctetString(encryptedDigest));
        SignedData signedData = new SignedData(new DERSet(signerInfo.getDigestAlgorithm()), encapContentInfo, null, null, new DERSet(signerInfo));

        ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.signedData, signedData);
        CMSSignedData cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(contentType, encryptedDigest), contentInfo);

        return cmsSignedData.getSignerInfos().getSigners().iterator().next();
    }
}
