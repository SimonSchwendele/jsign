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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.jsign.DigestAlgorithm;

/**
 * Verification result of a signed file.
 *
 * @since 8.0
 */
public class VerificationResult {

    private final List<SignatureVerification> signatureVerifications = new ArrayList<>();

    public List<SignatureVerification> getSignatureVerifications() {
        return signatureVerifications;
    }

    public boolean isValid() {
        if (signatureVerifications.isEmpty()) {
            return false;
        }

        for (SignatureVerification signatureVerification : signatureVerifications) {
            if (signatureVerification.isValid()) {
                return true;
            }
        }

        return false;
    }

    public static final class SignatureVerification {
        private final X509Certificate certificate;
        private final DigestAlgorithm digestAlgorithm;
        private final List<CheckResult> checks;

        SignatureVerification(CheckResult checks) {
            this(null, null, Collections.singletonList(checks));
        }

        SignatureVerification(X509Certificate certificate, DigestAlgorithm digestAlgorithm, List<CheckResult> checks) {
            this.certificate = certificate;
            this.digestAlgorithm = digestAlgorithm;
            this.checks = checks;
        }

        public X509Certificate getCertificate() {
            return certificate;
        }

        public DigestAlgorithm getDigestAlgorithm() {
            return digestAlgorithm;
        }

        public List<CheckResult> getChecks() {
            return checks;
        }

        public List<CheckResult> getIssues() {
            List<CheckResult> issues = new ArrayList<>();
            for (CheckResult check : checks) {
                if (check.getStatus() == CheckResult.Status.FAILED) {
                    issues.add(check);
                }
            }
            return issues;
        }

        public boolean isValid() {
            return getIssues().isEmpty();
        }
    }
}
