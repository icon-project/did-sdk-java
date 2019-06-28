package foundation.icon.did.exceptions;

import java.security.GeneralSecurityException;

public class AlgorithmException extends GeneralSecurityException {

    public AlgorithmException(String message) {
        super(message);
    }

    public AlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }

    public AlgorithmException(Throwable cause) {
        super(cause);
    }
}
