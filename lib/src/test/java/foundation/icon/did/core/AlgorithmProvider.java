package foundation.icon.did.core;

import foundation.icon.icx.crypto.LinuxSecureRandom;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * For test
 */
@SuppressWarnings("Duplicates")
public class AlgorithmProvider {

    public static final String PROVIDER = "BC";

    private static final SecureRandom SECURE_RANDOM;
    private static int isAndroid = -1;

    public static final double MIN_BOUNCY_CASTLE_VERSION = 1.54;

    static {

        if (isAndroidRuntime()) {
            new LinuxSecureRandom();
        }

        SECURE_RANDOM = new SecureRandom();

        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        Provider newProvider = new BouncyCastleProvider();

        if (newProvider.getVersion() < MIN_BOUNCY_CASTLE_VERSION) {
            String message = String.format(
                    "The version of BouncyCastle should be %f or newer", MIN_BOUNCY_CASTLE_VERSION);
            throw new RuntimeCryptoException(message);
        }

        if (provider != null) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }

        Security.addProvider(newProvider);

    }


    public static Algorithm create(Type type) {
        if (type == null) {
            throw new IllegalArgumentException("type cannot be null.");
        }
        switch (type) {
            case RS256:
                return new RS256Algorithm();
            case ES256:
                return new ES256Algorithm();
            case ES256K:
                return new ES256KAlgorithm();
            case NONE:
                return new NoneAlgorithm();
            default:
                throw new IllegalArgumentException("cannot create sigAlgorithm for " + type);
        }
    }

    public enum Type {
        RS256("RsaVerificationKey2018", "SHA256withRSA", "RSA"),
        ES256("Secp256r1VerificationKey", "SHA256withECDSA", "EC"),
        ES256K("Secp256k1VerificationKey", "SHA256withECDSA", "EC"),
        NONE("none", "none", "none");

        private String identifier;
        private String sigAlgorithm;
        private String keyAlgorithm;

        Type(String identifier, String sigAlgorithm, String keyAlgorithm) {
            this.identifier = identifier;
            this.sigAlgorithm = sigAlgorithm;
            this.keyAlgorithm = keyAlgorithm;
        }

        public String getName() {
            return name();
        }

        public String getIdentifier() {
            return identifier;
        }

        public String getSigAlgorithm() {
            return sigAlgorithm;
        }

        public String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        public static Type fromName(String name) {
            if (name != null) {
                for (Type t : Type.values()) {
                    if (name.equalsIgnoreCase(t.getName())) {
                        return t;
                    }
                }
            }
            return null;
        }

        public static Type fromIdentifier(String identifier) {
            if (identifier != null) {
                for (Type t : Type.values()) {
                    if (identifier.equalsIgnoreCase(t.getIdentifier())) {
                        return t;
                    }
                }
            }
            return null;
        }
    }

    public static SecureRandom secureRandom() {
        return SECURE_RANDOM;
    }

    public static boolean isAndroidRuntime() {
        if (isAndroid == -1) {
            final String runtime = System.getProperty("java.runtime.name");
            isAndroid = (runtime != null && runtime.equals("Android Runtime")) ? 1 : 0;
        }
        return isAndroid == 1;
    }
}
