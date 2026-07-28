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
import java.util.logging.Logger;

/**
 * Verification rule for a signature.
 *
 * @since 8.0
 */
abstract class VerificationRule {

    protected Logger log = Logger.getLogger(getClass().getName());

    /**
     * Returns the name of the rule (based on the name of the class by default)
     */
    public String getName() {
        return getClass().getSimpleName().replaceAll("Rule$", "").replaceAll("(?<!^)(?=[A-Z])", " ");
    }

    /**
     * Performs a verification check on a signature.
     *
     * @param context the verification context of the signature
     */
    public abstract CheckResult check(VerificationContext context) throws IOException;
}
