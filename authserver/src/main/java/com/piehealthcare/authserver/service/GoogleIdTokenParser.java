package com.piehealthcare.authserver.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

import java.util.Collections;
import java.util.Map;

public class GoogleIdTokenParser {

    private static final String CLIENT_ID = "842949735720-tn0ure1c1hngol0m7mmrj2tifklm6h56.apps.googleusercontent.com";

    public static Map<String, Object> parseIdToken(String idTokenString) {
        try {
            // JSON 및 HTTP 전송 객체 생성
            JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
            NetHttpTransport transport = new NetHttpTransport();

            // GoogleIdTokenVerifier 생성
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                    .setAudience(Collections.singletonList(CLIENT_ID)) // 클라이언트 ID 설정
                    .build();

            // ID Token 검증 및 파싱
            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken == null) {
                throw new RuntimeException("Invalid ID token");
            }

            // 사용자 정보 가져오기
            GoogleIdToken.Payload payload = idToken.getPayload();

            // 사용자 정보 맵으로 반환
            Map<String, Object> userInfo = Map.of(
                    "sub", payload.getSubject(), // Google 사용자 고유 ID
                    "email", payload.getEmail(), // 사용자 이메일
                    "email_verified", payload.getEmailVerified(), // 이메일 검증 여부
                    "name", payload.get("name") // 사용자 이름
            );

            return userInfo;
        } catch (Exception e) {
            throw new RuntimeException("Error parsing ID token", e);
        }
    }
}
