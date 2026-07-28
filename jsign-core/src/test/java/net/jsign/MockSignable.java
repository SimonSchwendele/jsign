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
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Hex;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;

public class MockSignable implements Signable {

    private final Map<DigestAlgorithm, byte[]> digests = new HashMap<>();
    private List<CMSSignedData> signatures = new ArrayList<>();

    public void setDigest(DigestAlgorithm algorithm, String digest) {
        digests.put(algorithm, Hex.decode(digest));
    }

    public byte[] computeDigest(DigestAlgorithm digestAlgorithm) {
        byte[] digest = digests.get(digestAlgorithm);
        if (digest == null) {
            return digestAlgorithm.getMessageDigest().digest();
        }
        return digest;
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm));
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());

        return new SpcIndirectDataContent(data, digestInfo);
    }

    @Override
    public List<CMSSignedData> getSignatures() {
        return signatures;
    }

    @Override
    public void setSignatures(List<CMSSignedData> signatures) {
        this.signatures = signatures;
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        this.signatures = SignatureUtils.getSignatures(signature);
    }

    public void attachSignatures(File detachedSignature) throws IOException {
        byte[] signatureBytes = Files.readAllBytes(detachedSignature.toPath());
        setSignatures(SignatureUtils.getSignatures(signatureBytes));
    }

    @Override
    public void save() {
    }

    @Override
    public void close() {
    }
}
