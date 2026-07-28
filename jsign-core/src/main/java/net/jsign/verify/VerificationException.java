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

import net.jsign.CommandException;

/**
 * Exception thrown when the signature verification fails.
 *
 * @since 8.0
 */
public class VerificationException extends CommandException {

    private static final long serialVersionUID = 3135550267206807847L;

    /**
     * Error code:
     * <ul>
     *   <li>bit 0: execution error</li>
     *   <li>bit 1: the file is not signed</li>
     *   <li>bit 2: all signatures are invalid</li>
     * </ul> 
     */
    private final int errorCode;

    public VerificationException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
