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

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;

/**
 * Verification context of a signature.
 *
 * @since 8.0
 */
class VerificationContext {
    private final Signable signable;
    private final Map<DigestAlgorithm, byte[]> digestCache;
    private final CMSSignedData signature;
    private final SignerInformation signerInformation;
    private final X509Certificate signerCertificate;
    private CertPath certPath;
    private Date date = new Date();

    public VerificationContext(Signable signable, Map<DigestAlgorithm, byte[]> digestCache, CMSSignedData signature, SignerInformation signerInformation, X509Certificate signerCertificate) {
        this.signable = signable;
        this.digestCache = digestCache;
        this.signature = signature;
        this.signerInformation = signerInformation;
        this.signerCertificate = signerCertificate;
    }

    public Signable getSignable() {
        return signable;
    }

    public Map<DigestAlgorithm, byte[]> getDigestCache() {
        return digestCache;
    }

    public CMSSignedData getSignature() {
        return signature;
    }

    public SignerInformation getSignerInformation() {
        return signerInformation;
    }

    public X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    public CertPath getCertPath() {
        return certPath;
    }

    public void setCertPath(CertPath certPath) {
        this.certPath = certPath;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }
}
