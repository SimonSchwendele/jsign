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

/**
 * Result of a verification rule.
 *
 * @since 8.0
 */
public class CheckResult {

    public enum Status {
        PASSED,
        FAILED,
        SKIPPED
    }

    /** The name of the rule*/
    private final String rule;

    private final Status status;
    private final String message;
    private final String expected;
    private final String actual;
    private final Throwable error;

    public CheckResult(String rule, Status status, String message) {
        this(rule, status, message, null, null, null);
    }

    public CheckResult(String rule, Status status, String message, Throwable error) {
        this(rule, status, message, null, null, error);
    }

    public CheckResult(String rule, Status status, String message, String expected, String actual) {
        this(rule, status, message, expected, actual, null);
    }

    public CheckResult(String rule, Status status, String message, String expected, String actual, Throwable error) {
        this.rule = rule;
        this.status = status;
        this.message = message;
        this.expected = expected;
        this.actual = actual;
        this.error = error;
    }

    public String getRule() {
        return rule;
    }

    public Status getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public String getExpected() {
        return expected;
    }

    public String getActual() {
        return actual;
    }

    public Throwable getError() {
        return error;
    }

    public String toString() {
        StringBuilder buffer = new StringBuilder();
        buffer.append("[CheckResult rule=").append(rule);
        buffer.append(", status=").append(status);
        buffer.append(", message=").append(message);
        if (expected != null) {
            buffer.append(", expected=").append(expected);
        }
        if (actual != null) {
            buffer.append(", actual=").append(actual);
        }
        if (error != null) {
            buffer.append(", error=").append(error);
        }
        buffer.append("]");
        return buffer.toString();
    }
}
