/*
 * Copyright 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package net.jsign.verify;

import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPException;

/**
 * This class is a minimized copy of the org.bouncycastle.tsp.TimeStampTokenInfo class from Bouncy Castle.
 * The original class has a package-private constructor, which prevents direct instantiation.
 *
 * @since 8.0
 */
class AuthenticodeTimeStampTokenInfo {
    TSTInfo tstInfo;
    Date genTime;

    AuthenticodeTimeStampTokenInfo(TSTInfo tstInfo) throws TSPException {
        this.tstInfo = tstInfo;

        try {
            this.genTime = tstInfo.getGenTime().getDate();
        } catch (ParseException e) {
            throw new TSPException("unable to parse genTime field");
        }
    }

    public Date getGenTime() {
        return genTime;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return tstInfo.getMessageImprint().getHashAlgorithm();
    }

    public byte[] getMessageImprintDigest() {
        return tstInfo.getMessageImprint().getHashedMessage();
    }
}
