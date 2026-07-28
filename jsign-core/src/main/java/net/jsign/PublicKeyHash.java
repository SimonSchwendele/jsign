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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.bouncycastle.util.encoders.Hex;

import static java.nio.charset.StandardCharsets.*;

/**
 * SHA-256 hash of the Subject Public Key Information (SPKI) of a certificate.
 *
 * @since 8.0
 */
public class PublicKeyHash {

    private final byte[] hash;

    public PublicKeyHash(byte[] hash) {
        Objects.requireNonNull(hash);
        this.hash = hash;
    }

    public PublicKeyHash(String hash) {
        this(Hex.decode(hash));
    }

    public PublicKeyHash(X509Certificate certificate) {
        this(DigestAlgorithm.SHA256.getMessageDigest().digest(certificate.getPublicKey().getEncoded()));
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof PublicKeyHash)) {
            return false;
        }
        PublicKeyHash that = (PublicKeyHash) o;
        return Arrays.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }

    @Override
    public String toString() {
        return Hex.toHexString(hash);
    }

    /**
     * Loads the specified TSV file containing public key hashes on the first column.
     *
     * @param file the TSV file to load
     * @return a set of public key hashes
     */
    public static Set<PublicKeyHash> load(File file) throws IOException {
        try (InputStream in = Files.newInputStream(file.toPath())) {
            return load(in);
        }
    }

    /**
     * Loads the specified TSV input stream containing public key hashes on the first column.
     *
     * @param inputStream the input stream to load
     * @return a set of public key hashes
     */
    public static Set<PublicKeyHash> load(InputStream inputStream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, UTF_8))) {
            return reader.lines()
                    .filter(line -> !line.startsWith("#") && !line.trim().isEmpty())
                    .map(line -> line.split("\t")[0])
                    .map(PublicKeyHash::new)
                    .collect(Collectors.toSet());
        }
    }
}
