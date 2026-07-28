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

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;

import static net.jsign.verify.CheckResult.Status.*;

/**
 * Verification rules checking if the signature is cryptographically valid.
 *
 * @since 8.0
 */
class SignatureIntegrityRule extends VerificationRule {

    @Override
    public CheckResult check(VerificationContext context) throws IOException {
        SignerInformation signerInformation = context.getSignature().getSignerInfos().getSigners().iterator().next();

        try {
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().build(context.getSignerCertificate());
            signerInformation.verify(verifier);

            return new CheckResult(getName(), PASSED, "Signature data is valid");
        } catch (OperatorCreationException | CMSException e) {
            return new CheckResult(getName(), FAILED, "Signature data is invalid", e);
        }
    }
}
