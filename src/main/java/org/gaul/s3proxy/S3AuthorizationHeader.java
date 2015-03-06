/*
 * Copyright 2014 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import com.google.common.collect.ImmutableMap;

public class S3AuthorizationHeader {
    String hmacAlgorithm = null;
    String hashAlgorithm = null;
    String region = null;
    String date = null;
    String service = null;
    String identity = null;
    String signature = null;

    private enum V4_SCOPE_FIELDS { IDENTITY, DATE, REGION, SERVICE };
    private final ImmutableMap<V4_SCOPE_FIELDS, Integer> V4_FIELD_MAP =
            new ImmutableMap.Builder<V4_SCOPE_FIELDS, Integer>().
            put(V4_SCOPE_FIELDS.IDENTITY, 0).
            put(V4_SCOPE_FIELDS.DATE, 1).
            put(V4_SCOPE_FIELDS.REGION, 2).
            put(V4_SCOPE_FIELDS.SERVICE, 3).
            build();

    private ImmutableMap<String, String> digestMap = ImmutableMap.
            <String, String>builder().
            put("SHA256", "SHA-256").
            put("SHA1", "SHA-1").
            put("MD5", "MD5").
            build();

    private String SIGNATURE_FIELD = "Signature=";
    private String CREDENTIAL_FIELD = "Credential=";

    S3AuthorizationHeader(String header) throws IllegalArgumentException {
        if (!header.startsWith("AWS")) {
            throw new IllegalArgumentException("Invalid header");
        }
        if (header.startsWith("AWS ")) {
            // AWS v2 header
            String[] fields = header.split(" ");
            if (fields.length != 2) {
                throw new IllegalArgumentException("Invalid header");
            }
            String[] identityTuple = fields[1].split(":");
            if (identityTuple.length != 2) {
                throw new IllegalArgumentException("Invalid header");
            }
            identity = identityTuple[0];
            signature = identityTuple[1];
            return;
        }
        if (!header.startsWith("AWS4-HMAC")) {
            throw new IllegalArgumentException("Invalid header");
        }
        extractScopeFields(header);
        extractSignature(header);
    }

    @Override
    public String toString() {
        StringBuilder authString = new StringBuilder();
        authString.append("Identity: " + identity);
        authString.append("; Signature: " + signature);
        authString.append("; HMAC algorithm: " + hmacAlgorithm);
        authString.append("; Hash algorithm: " + hashAlgorithm);
        authString.append("; region: " + region);
        authString.append("; date: " + date);
        authString.append("; service " + service);
        return authString.toString();
    }

    private void extractSignature(String header) throws
            IllegalArgumentException {
        int signatureIndex = header.indexOf(SIGNATURE_FIELD);
        if (signatureIndex < 0) {
            throw new IllegalArgumentException("Invalid signature");
        }
        signatureIndex += SIGNATURE_FIELD.length();
        int signatureEnd = header.indexOf(signatureIndex, ',');
        if (signatureEnd < 0) {
            signature = header.substring(signatureIndex);
        } else {
            signature = header.substring(signatureIndex, signatureEnd);
        }
    }

    private void extractScopeFields(String header) throws
            IllegalArgumentException {
        int credentialIndex = header.indexOf(CREDENTIAL_FIELD);
        if (credentialIndex < 0) {
            throw new IllegalArgumentException("Invalid header");
        }
        int credentialEnd = header.indexOf(',', credentialIndex);
        if (credentialEnd < 0) {
            throw new IllegalArgumentException("Invalid header");
        }
        String credential = header.substring(credentialIndex +
                CREDENTIAL_FIELD.length(), credentialEnd);
        String fields[] = credential.split("/");
        if (fields.length < V4_FIELD_MAP.size()) {
            throw new IllegalArgumentException("Invalid Credential");
        }
        region = fields[V4_FIELD_MAP.get(V4_SCOPE_FIELDS.REGION)];
        date = fields[V4_FIELD_MAP.get(V4_SCOPE_FIELDS.DATE)];
        service = fields[V4_FIELD_MAP.get(V4_SCOPE_FIELDS.SERVICE)];
        String awsSignatureVersion = header.substring(0, header.indexOf(' '));
        hashAlgorithm = digestMap.get(awsSignatureVersion.split("-")[2]);
        hmacAlgorithm = "Hmac" + awsSignatureVersion.split("-")[2];
        identity = fields[V4_FIELD_MAP.get(V4_SCOPE_FIELDS.IDENTITY)];
    }
}
