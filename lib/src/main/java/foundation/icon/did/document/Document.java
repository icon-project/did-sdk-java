package foundation.icon.did.document;

import java.util.List;
import java.util.Map;

/**
 * This corresponds to the publicKeys property of the DIDs specification.
 * https://w3c-ccg.github.io/did-spec/#did-documents
 */
public class Document {

    private String id;
    private long created;
    private long updated;
    private Map<String, PublicKeyProperty> publicKey;
    private List<AuthenticationProperty> authentication;

    private Document(Builder builder) {
        id = builder.id;
        created = builder.created;
        updated = builder.updated;
        publicKey = builder.publicKey;
        authentication = builder.authentication;
    }

    public String getId() {
        return id;
    }

    public long getCreated() {
        return created;
    }

    public long getUpdated() {
        return updated;
    }

    public Map<String, PublicKeyProperty> getPublicKeyProperty() {
        return publicKey;
    }

    public PublicKeyProperty getPublicKeyProperty(String publicKeyId) {
        return publicKey.get(publicKeyId);
    }

    public List<AuthenticationProperty> getAuthentication() {
        return authentication;
    }

    public String toJson() {
        return Converters.gson().toJson(this);
    }


    public static final class Builder {
        private String id;
        private long created;
        private long updated;
        private Map<String, PublicKeyProperty> publicKey;
        private List<AuthenticationProperty> authentication;

        public Builder() {
        }

        public Builder id(String val) {
            id = val;
            return this;
        }

        public Builder created(long val) {
            created = val;
            return this;
        }

        public Builder updated(long val) {
            updated = val;
            return this;
        }

        public Builder publicKey(Map<String, PublicKeyProperty> val) {
            publicKey = val;
            return this;
        }

        public Builder authentication(List<AuthenticationProperty> val) {
            authentication = val;
            return this;
        }

        public Document build() {
            return new Document(this);
        }
    }

    @Override
    public String toString() {
        return "Document{" +
                "id='" + id + '\'' +
                ", created=" + created +
                ", updated=" + updated +
                ", publicKey=" + publicKey +
                ", authentication=" + authentication +
                '}';
    }
}
