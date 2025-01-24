package com.piehealthcare.authserver.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

import java.util.Collections;

public class GoogleIdTokenVerifierUtil {

    private static final String CLIENT_ID = "YOUR_ANDROID_CLIENT_ID";

    public static GoogleIdToken.Payload verifyToken(String idTokenString) {
        try {
            JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), jsonFactory)
                    .setAudience(Collections.singletonList(CLIENT_ID))
                    .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken != null) {
                return idToken.getPayload(); // 검증된 사용자 정보 반환
            } else {
                throw new RuntimeException("Invalid ID Token.");
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to verify ID Token.", e);
        }
    }
}
