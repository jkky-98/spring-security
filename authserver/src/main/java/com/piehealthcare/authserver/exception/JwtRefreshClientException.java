package com.piehealthcare.authserver.exception;

public class JwtRefreshClientException extends RuntimeException {
    public JwtRefreshClientException(String message) {
        super(message);
    }
}
