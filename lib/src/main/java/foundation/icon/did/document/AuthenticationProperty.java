package foundation.icon.did.document;

/**
 * This corresponds to the authentication property of the DIDs specification.
 * https://w3c-ccg.github.io/did-spec/#authentication
 */
public class AuthenticationProperty {
    String type;
    String publicKey;

    private AuthenticationProperty(Builder builder) {
        type = builder.type;
        publicKey = builder.publicKey;
    }

    public String getType() {
        return type;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public static final class Builder {
        private String type;
        private String publicKey;

        public Builder() {
        }

        public Builder type(String val) {
            type = val;
            return this;
        }

        public Builder publicKey(String val) {
            publicKey = val;
            return this;
        }

        public AuthenticationProperty build() {
            return new AuthenticationProperty(this);
        }
    }

    @Override
    public String toString() {
        return "AuthenticationProperty{" +
                "type=" + type +
                ", publicKey='" + publicKey + '\'' +
                '}';
    }
}

