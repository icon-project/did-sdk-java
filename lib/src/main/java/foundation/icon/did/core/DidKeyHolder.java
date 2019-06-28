package foundation.icon.did.core;

import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.jwt.Jwt;
import org.bouncycastle.util.encoders.Hex;

import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * This class holds the private key corresponding to the publicKey registered in the DID Document.*
 *
 * <p>
 * To find a privateKey that matches a publicKey registered in a block chain,
 * it needs the id of DID document and the id of publicKey.
 *
 * It is responsible for signing Jwt with the privateKey you have.
 */
public class DidKeyHolder {

    private String did;
    private String keyId;
    private AlgorithmProvider.Type type;
    private PrivateKey privateKey;

    private DidKeyHolder(Builder builder) {
        did = builder.did;
        keyId = builder.keyId;
        type = builder.type;
        privateKey = builder.privateKey;
    }

    public String getDid() {
        return did;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getKid() {
        return did + "#" + keyId;
    }

    public AlgorithmProvider.Type getType() {
        return type;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Create a signature and encoded jwt
     *
     * @param jwt the Jwt object
     * @return the encoded jwt
     */
    public String sign(Jwt jwt) throws AlgorithmException {
        return jwt.sign(privateKey);
    }

    @Override
    public String toString() {
        Algorithm algorithm = AlgorithmProvider.create(type);
        String priv = (privateKey == null) ? "" :
                Hex.toHexString(algorithm.privateKeyToByte(privateKey));
        return "DidKeyHolder{" +
                "did='" + did + '\'' +
                ", keyId='" + keyId + '\'' +
                ", type=" + type +
                ", privateKey=" + priv +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DidKeyHolder)) return false;
        DidKeyHolder keyHolder = (DidKeyHolder) o;
        Algorithm algorithm = AlgorithmProvider.create(type);
        return Objects.equals(did, keyHolder.did) &&
                Objects.equals(keyId, keyHolder.keyId) &&
                type == keyHolder.type &&
                Arrays.equals(algorithm.privateKeyToByte(privateKey),
                        algorithm.privateKeyToByte(keyHolder.privateKey));
    }

    @Override
    public int hashCode() {
        return Objects.hash(did, keyId, type, privateKey);
    }

    public static final class Builder {
        private String did;
        private String keyId;
        private AlgorithmProvider.Type type;
        private PrivateKey privateKey;

        public Builder() {
        }

        public Builder(KeyProvider provider) {
            this.keyId = provider.getKeyId();
            this.type = provider.getType();
            this.privateKey = provider.getPrivateKey();
        }

        public Builder did(String val) {
            did = val;
            return this;
        }

        public Builder keyId(String val) {
            keyId = val;
            return this;
        }

        public Builder type(AlgorithmProvider.Type val) {
            type = val;
            return this;
        }

        public Builder privateKey(PrivateKey val) {
            privateKey = val;
            return this;
        }

        public DidKeyHolder build() {
            checkArgument(did, "did not found");
            checkArgument(privateKey, "privateKey not found");
            checkArgument(keyId, "keyId not found");
            checkArgument(type, "type not found");

            return new DidKeyHolder(this);
        }

        public static <T> void checkArgument(T object, String message) {
            if (object == null) {
                throw new IllegalArgumentException(message);
            }
        }
    }
}
