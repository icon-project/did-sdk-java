package foundation.icon.did.core;

import org.bouncycastle.util.encoders.Hex;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * Generic Public/Private Key provider.
 * {@linkplain Algorithm#generateKeyProvider(String)}
 */
public class KeyProvider {
    private String keyId;
    private AlgorithmProvider.Type type;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    private KeyProvider(Builder builder) {
        keyId = builder.keyId;
        type = builder.type;
        publicKey = builder.publicKey;
        privateKey = builder.privateKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public AlgorithmProvider.Type getType() {
        return type;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public Builder newBuilder() {
        return new Builder(this);
    }

    public static final class Builder {
        private String keyId;
        private AlgorithmProvider.Type type;
        private PublicKey publicKey;
        private PrivateKey privateKey;

        public Builder() {
        }

        public Builder(KeyProvider keyProvider) {
            keyId = keyProvider.keyId;
            type = keyProvider.type;
            publicKey = keyProvider.publicKey;
            privateKey = keyProvider.privateKey;
        }

        public Builder keyId(String val) {
            keyId = val;
            return this;
        }

        public Builder type(AlgorithmProvider.Type val) {
            type = val;
            return this;
        }

        public Builder publicKey(PublicKey val) {
            publicKey = val;
            return this;
        }

        public Builder privateKey(PrivateKey val) {
            privateKey = val;
            return this;
        }

        public KeyProvider build() {
            if (keyId == null) throw new IllegalArgumentException("keyId cannot be null.");
            if (type == null) throw new IllegalArgumentException("type cannot be null.");
            return new KeyProvider(this);
        }
    }

    @Override
    public String toString() {
        Algorithm algorithm = AlgorithmProvider.create(type);
        String pub = (publicKey == null) ? "" :
                Hex.toHexString(algorithm.publicKeyToByte(publicKey));
        String priv = (privateKey == null) ? "" :
                Hex.toHexString(algorithm.privateKeyToByte(privateKey));
        return "KeyProvider{" +
                "keyId='" + keyId + '\'' +
                ", type=" + type +
                ", publicKey=" + pub +
                ", privateKey=" + priv +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyProvider)) return false;
        KeyProvider that = (KeyProvider) o;

        Algorithm algorithm = AlgorithmProvider.create(type);

        return Objects.equals(keyId, that.keyId) &&
                type == that.type &&
                Arrays.equals(algorithm.publicKeyToByte(publicKey),
                        algorithm.publicKeyToByte(that.publicKey)) &&
                Arrays.equals(algorithm.privateKeyToByte(privateKey),
                        algorithm.privateKeyToByte(that.privateKey));
    }

    @Override
    public int hashCode() {
        Algorithm algorithm = AlgorithmProvider.create(type);
        return Objects.hash(keyId, type.name(),
                algorithm.publicKeyToByte(publicKey),
                algorithm.privateKeyToByte(privateKey));
    }
}
