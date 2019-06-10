package com.fastchar.security.exception;

public class FastSecurityException extends RuntimeException {
    public FastSecurityException() {
    }

    public FastSecurityException(String message) {
        super(message);
    }

    public FastSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public FastSecurityException(Throwable cause) {
        super(cause);
    }

    public FastSecurityException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
