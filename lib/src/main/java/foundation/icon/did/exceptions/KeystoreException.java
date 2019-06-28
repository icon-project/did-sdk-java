package foundation.icon.did.exceptions;

/**
 * Original Code
 * https://github.com/web3j/web3j/blob/master/crypto/src/main/java/org/web3j/crypto/CipherException.java
 */
public class KeystoreException extends Exception {

    public KeystoreException(String message) {
        super(message);
    }

    KeystoreException(Throwable cause) {
        super(cause);
    }

    public KeystoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
