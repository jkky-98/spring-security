package com.piehealthcare.authserver.exception;

public class JwtExpiredException extends RuntimeException {

    private final String expiredToken;

    public JwtExpiredException(String message, String expiredToken) {
        super(message);
        this.expiredToken = expiredToken;
    }
    public String getExpiredToken() {
        return expiredToken;
    }
}
