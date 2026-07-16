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

package net.jsign.asn1.authenticode;

import java.io.File;
import java.util.Date;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static org.junit.Assert.*;

public class CertificateTrustListTest {

    private ASN1EncodableVector createAttribute(String oid, ASN1Encodable value) {
        ASN1EncodableVector attributeValues = new ASN1EncodableVector();
        attributeValues.add(value);

        ASN1EncodableVector attribute = new ASN1EncodableVector();
        attribute.add(new ASN1ObjectIdentifier(oid));
        attribute.add(new DERSet(attributeValues));

        return attribute;
    }

    private ASN1EncodableVector createTrustedSubject(String subjectIdentifier, ASN1EncodableVector attribute) {
        ASN1EncodableVector trustedSubject = new ASN1EncodableVector();
        trustedSubject.add(new DEROctetString(Hex.decode(subjectIdentifier)));
        trustedSubject.add(new DERSet(new DERSequence(attribute)));
        return trustedSubject;
    }

    @Test
    public void testParseCertificateTrustList() {
        ASN1EncodableVector attribute = createAttribute("1.3.6.1.4.1.311.10.11.11", new DEROctetString(new byte[] {0x01, 0x02, 0x03}));

        ASN1EncodableVector trustedSubject = createTrustedSubject("101112131415161718191A1B1C1D1E1F20212223", attribute);

        ASN1EncodableVector subjectUsage = new ASN1EncodableVector();
        subjectUsage.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.3"));

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(1));
        vector.add(new DERSequence(subjectUsage));
        vector.add(new DEROctetString(new byte[] {0x01, 0x02}));
        vector.add(new ASN1Integer(42));
        vector.add(new DERGeneralizedTime("20260101000000Z"));
        vector.add(new DERGeneralizedTime("20270101000000Z"));
        vector.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
        vector.add(new DERSequence(new DERSequence(trustedSubject)));


        CertificateTrustList ctl = new CertificateTrustList(ASN1Sequence.getInstance(new DERSequence(vector)));

        assertEquals("version", 1, ctl.getVersion().intValue());
        assertEquals("number of subject usages", 1, ctl.getSubjectUsage().size());
        assertEquals("subject usage", "1.3.6.1.5.5.7.3.3", ctl.getSubjectUsage().get(0).getId());
        assertArrayEquals("list identifier", new byte[] {0x01, 0x02}, ctl.getListIdentifier().getOctets());
        assertEquals("sequence number", 42, ctl.getSequenceNumber().intValue());
        assertEquals("update time", new Date(1767225600000L), ctl.getCtlThisUpdate().getDate());
        assertEquals("next update time", new Date(1798761600000L), ctl.getCtlNextUpdate().getDate());
        assertEquals("subject algorithm", "1.2.840.113549.1.1.11", ctl.getSubjectAlgorithm().getAlgorithm().getId());
        assertEquals("number of trusted subjects", 1, ctl.getTrustedSubjects().size());

        Attribute parsedAttribute = ctl.getTrustedSubjects().get(0).getAttributes().get(0);
        assertEquals("oid of the first attribute", "1.3.6.1.4.1.311.10.11.11", parsedAttribute.getAttrType().getId());
        assertEquals(1, parsedAttribute.getAttrValues().size());
        assertTrue(parsedAttribute.getAttrValues().getObjectAt(0) instanceof DEROctetString);
    }

    @Test
    public void testParseAuthRootSTL() throws Exception {
        byte[] data = FileUtils.readFileToByteArray(new File("src/test/resources/keystores/authroot.stl"));
        ASN1Sequence content = (ASN1Sequence) new CMSSignedData(data).getSignedContent().getContent();
        CertificateTrustList ctl = new CertificateTrustList(content);

        assertEquals("version", 1, ctl.getVersion().intValue());
        assertEquals("number of trusted subjects", 554, ctl.getTrustedSubjects().size());

        TrustedSubject trustedSubject = ctl.getTrustedSubjects().get(0);
        assertEquals("Friendly name", "Microsoft Root Certificate Authority", trustedSubject.getFriendlyName());
        assertEquals("Subject identifier", "cdd4eeae6000ac7f40c3802c171e30148030c072", Hex.toHexString(trustedSubject.getSubjectIdentifier()));

        trustedSubject = ctl.getTrustedSubjects().get(150);
        assertTrue("Enhanced key usage - Code signing", trustedSubject.getEnhancedKeyUsage().hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning));
    }
}
