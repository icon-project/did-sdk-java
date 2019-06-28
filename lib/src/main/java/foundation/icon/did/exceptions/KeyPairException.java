package foundation.icon.did.exceptions;

import java.security.GeneralSecurityException;

public class KeyPairException extends GeneralSecurityException {
    public KeyPairException(String msg) {
        super(msg);
    }
}
