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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;

/**
 * Trusted subject of a Certificate Trust List.
 *
 * <pre>
 * TrustedSubject ::= SEQUENCE {
 *     subjectIdentifier    OCTET STRING,
 *     attributes           SET OF Attribute OPTIONAL
 * }
 *
 * Attribute ::= SEQUENCE {
 *     type                 OBJECT IDENTIFIER,
 *     values               SET OF ANY
 * }
 * </pre>
 *
 * @since 8.0
 */
public class TrustedSubject {

    public static final ASN1ObjectIdentifier CERT_MD5_HASH_PROP_ID                      = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.4");
    public static final ASN1ObjectIdentifier CERT_ENHKEY_USAGE_PROP_ID	                = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.9");
    public static final ASN1ObjectIdentifier CERT_FRIENDLY_NAME_PROP_ID                 = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.11");
    public static final ASN1ObjectIdentifier CERT_SIGNATURE_HASH_PROP_ID                = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.15");
    public static final ASN1ObjectIdentifier CERT_KEY_IDENTIFIER_PROP_ID                = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.20");
    public static final ASN1ObjectIdentifier CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.28");
    public static final ASN1ObjectIdentifier CERT_SUBJECT_NAME_MD5_HASH_PROP_ID         = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.29");
    public static final ASN1ObjectIdentifier CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID    = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.83");
    public static final ASN1ObjectIdentifier CERT_DISALLOWED_FILETIME_PROP_ID           = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.11.104");

    /** The SHA-1 thumbprint of the certificate. */
    private final byte[] subjectIdentifier;

    /** Certificate metadata (enhanced key usage, friendly name, etc.) */
    private final List<Attribute> attributes = new ArrayList<>();

    public TrustedSubject(ASN1Encodable encodable) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(encodable);
        subjectIdentifier = ASN1OctetString.getInstance(sequence.getObjectAt(0)).getOctets();

        if (sequence.size() > 1) {
            ASN1Set attributeSet = ASN1Set.getInstance(sequence.getObjectAt(1));
            for (ASN1Encodable attribute : attributeSet) {
                attributes.add(Attribute.getInstance(attribute));
            }
        }
    }

    public byte[] getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public List<Attribute> getAttributes() {
        return attributes;
    }

    public ASN1Set getAttributeValues(ASN1ObjectIdentifier oid) {
        for (Attribute attribute : attributes) {
            if (attribute.getAttrType().equals(oid)) {
                return attribute.getAttrValues();
            }
        }
        return null;
    }

    public String getFriendlyName() {
        ASN1Set values = getAttributeValues(CERT_FRIENDLY_NAME_PROP_ID);
        if (values == null) {
            return null;
        }

        ASN1OctetString octets = (ASN1OctetString) values.getObjectAt(0);
        return new String(octets.getOctets(), StandardCharsets.UTF_16LE).trim();
    }

    public ExtendedKeyUsage getEnhancedKeyUsage() {
        ASN1Set values = getAttributeValues(CERT_ENHKEY_USAGE_PROP_ID);
        if (values == null) {
            return null;
        }

        ASN1OctetString octets = (ASN1OctetString) values.getObjectAt(0);
        return ExtendedKeyUsage.getInstance(octets.getOctets());
    }
}
