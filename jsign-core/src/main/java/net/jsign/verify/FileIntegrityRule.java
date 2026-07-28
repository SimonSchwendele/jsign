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
import java.util.Arrays;

import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.util.encoders.Hex;

import net.jsign.DigestAlgorithm;
import net.jsign.SignatureUtils;

import static net.jsign.verify.CheckResult.Status.*;

/**
 * Verification rule checking if the computed digest of the signed file matches the digest in the signature.
 *
 * @since 8.0
 */
class FileIntegrityRule extends VerificationRule {

    @Override
    public CheckResult check(VerificationContext context) throws IOException {
        DigestInfo digestInfo;
        try {
            digestInfo = SignatureUtils.getDigestInfo(context.getSignature());
        } catch (Exception e) {
            return new CheckResult(getName(), FAILED, "Failed to extract the digest information from the signature", e);
        }
        if (digestInfo == null) {
            return new CheckResult(getName(), FAILED, "No digest information found in the signature");
        }

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(digestInfo.getAlgorithmId().getAlgorithm());
        if (digestAlgorithm == null) {
            return new CheckResult(getName(), FAILED, "Unsupported digest algorithm: " + digestInfo.getAlgorithmId().getAlgorithm());
        }

        byte[] computedDigest = context.getDigestCache().get(digestAlgorithm);
        if (computedDigest == null) {
            computedDigest = context.getSignable().computeDigest(digestAlgorithm);
            context.getDigestCache().put(digestAlgorithm, computedDigest);
        }
        boolean matches = Arrays.equals(computedDigest, digestInfo.getDigest());
        if (matches) {
            return new CheckResult(getName(), PASSED, "The file digest matches the signature");
        } else {
            String expected = Hex.toHexString(digestInfo.getDigest());
            String actual = Hex.toHexString(computedDigest);
            return new CheckResult(getName(), FAILED, "The file digest does not match the signature", expected, actual);
        }
    }
}
