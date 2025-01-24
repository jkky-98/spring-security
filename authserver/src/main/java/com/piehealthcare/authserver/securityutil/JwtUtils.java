package com.piehealthcare.authserver.securityutil;

import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;

public class JwtUtils {

    public static Key getKeyFromSecret(String secretKey) {
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalArgumentException("Secret key cannot be null or empty");
        }

        // 헥사 문자열로부터 바이트 배열 변환
        byte[] keyBytes = hexStringToByteArray(secretKey);

        // 키 길이 확인
        if (keyBytes.length < 32) { // 최소 256비트(32바이트)
            throw new IllegalArgumentException("Secret key must be at least 256 bits");
        }

        // 바이트 배열을 HMAC 키로 변환
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // 헥사 문자열을 바이트 배열로 변환하는 헬퍼 메서드
    private static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
