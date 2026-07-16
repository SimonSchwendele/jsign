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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;

/**
 * Certificate Trust List
 *
 * <pre>
 * CertificateTrustList ::= SEQUENCE {
 *     version              INTEGER DEFAULT v1,
 *     subjectUsage         SubjectUsage,
 *     listIdentifier       OCTET STRING OPTIONAL,
 *     sequenceNumber       INTEGER OPTIONAL,
 *     ctlThisUpdate        ChoiceOfTime,
 *     ctlNextUpdate        ChoiceOfTime OPTIONAL,
 *     subjectAlgorithm     AlgorithmIdentifier,
 *     trustedSubjects      TrustedSubjects OPTIONAL
 * }
 *
 * SubjectUsage ::= SEQUENCE OF OBJECT IDENTIFIER
 * TrustedSubjects ::= SEQUENCE OF TrustedSubject
 * </pre>
 *
 * @since 8.0
 */
public class CertificateTrustList {

    private BigInteger version = BigInteger.ONE;
    private List<ASN1ObjectIdentifier> subjectUsage = new ArrayList<>();
    private ASN1OctetString listIdentifier;
    private BigInteger sequenceNumber;
    private Time ctlThisUpdate;
    private Time ctlNextUpdate;
    private AlgorithmIdentifier subjectAlgorithm;
    private List<TrustedSubject> trustedSubjects = new ArrayList<>();

    public CertificateTrustList(ASN1Sequence sequence) {
        int index = 0;

        // version
        if (sequence.size() > 0 && sequence.getObjectAt(0) instanceof ASN1Integer) {
            version = ASN1Integer.getInstance(sequence.getObjectAt(index++)).getValue();
        }

        // subject usage
        for (ASN1Encodable oid : ASN1Sequence.getInstance(sequence.getObjectAt(index++))) {
            subjectUsage.add(ASN1ObjectIdentifier.getInstance(oid));
        }

        // list identifier
        ASN1Encodable element = index < sequence.size() ? sequence.getObjectAt(index) : null;
        if (element instanceof ASN1OctetString) {
            listIdentifier = (ASN1OctetString) element;
            index++;
        }

        // sequence number
        element = index < sequence.size() ? sequence.getObjectAt(index) : null;
        if (element instanceof ASN1Integer) {
            sequenceNumber = ASN1Integer.getInstance(element).getValue();
            index++;
        }

        // ctlThisUpdate
        ctlThisUpdate = Time.getInstance(sequence.getObjectAt(index++));

        // ctlNextUpdate
        element = index < sequence.size() ? sequence.getObjectAt(index) : null;
        if (element instanceof ASN1UTCTime || element instanceof ASN1GeneralizedTime) {
            ctlNextUpdate = Time.getInstance(element);
            index++;
        }

        subjectAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(index++));

        // trusted subjects
        element = index < sequence.size() ? sequence.getObjectAt(index) : null;
        if (element instanceof ASN1Sequence) {
            for (ASN1Encodable trustedSubject : ASN1Sequence.getInstance(element)) {
                trustedSubjects.add(new TrustedSubject(trustedSubject));
            }
        }
    }

    public BigInteger getVersion() {
        return version;
    }

    public List<ASN1ObjectIdentifier> getSubjectUsage() {
        return subjectUsage;
    }

    public ASN1OctetString getListIdentifier() {
        return listIdentifier;
    }

    public BigInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public Time getCtlThisUpdate() {
        return ctlThisUpdate;
    }

    public Time getCtlNextUpdate() {
        return ctlNextUpdate;
    }

    public AlgorithmIdentifier getSubjectAlgorithm() {
        return subjectAlgorithm;
    }

    public List<TrustedSubject> getTrustedSubjects() {
        return trustedSubjects;
    }
}
