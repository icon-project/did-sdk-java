package foundation.icon.did.document;

import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;

import java.security.PublicKey;
import java.util.List;

/**
 * This corresponds to the publicKeys property of the DIDs specification.
 * https://w3c-ccg.github.io/did-spec/#public-keys
 */
public class PublicKeyProperty {

    private String id;
    private PublicKey publicKey;
    private List<String> type;
    private EncodeType encodeType;
    private long created;
    private long revoked;

    private PublicKeyProperty(Builder builder) {
        id = builder.id;
        publicKey = builder.publicKey;
        type = builder.type;
        encodeType = builder.encodeType;
        created = builder.created;
        revoked = builder.revoked;
    }

    public String getId() {
        return id;
    }

    public List<String> getType() {
        return type;
    }

    public AlgorithmProvider.Type getAlgorithmType() {
        return AlgorithmProvider.Type.fromIdentifier(type.get(0));
    }

    public long getCreated() {
        return created;
    }

    public long getRevoked() {
        return revoked;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public EncodeType getEncodeType() {
        return encodeType;
    }

    public boolean isRevoked() {
        return (revoked > 0);
    }

    @Override
    public String toString() {
        Algorithm algorithm = AlgorithmProvider.create(getAlgorithmType());
        String pub = encodeType.encode(algorithm.publicKeyToByte(publicKey));
        return "PublicKeyProperty{" +
                "id='" + id + '\'' +
                ", publicKey=" + pub +
                ", type='" + type + '\'' +
                ", encodeType=" + encodeType +
                ", created=" + created +
                ", revoked=" + revoked +
                '}';
    }


    public static final class Builder {
        private String id;
        private PublicKey publicKey;
        private List<String> type;
        private EncodeType encodeType;
        private long created;
        private long revoked;

        public Builder() {
        }

        public Builder id(String val) {
            id = val;
            return this;
        }

        public Builder publicKey(PublicKey val) {
            publicKey = val;
            return this;
        }

        public Builder type(List<String> val) {
            type = val;
            return this;
        }

        public Builder encodeType(EncodeType val) {
            encodeType = val;
            return this;
        }

        public Builder created(long val) {
            created = val;
            return this;
        }

        public Builder revoked(long val) {
            revoked = val;
            return this;
        }

        public PublicKeyProperty build() {
            if (id == null) throw new IllegalArgumentException("id cannot be null.");
            if (type == null) throw new IllegalArgumentException("type cannot be null.");
            if (publicKey == null) throw new IllegalArgumentException("publicKey cannot be null.");
            return new PublicKeyProperty(this);
        }
    }
}
