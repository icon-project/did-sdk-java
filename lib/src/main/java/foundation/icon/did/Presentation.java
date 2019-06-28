package foundation.icon.did;


import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.jwt.ConvertJwt;
import foundation.icon.did.jwt.IssuerDid;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.jwt.Payload;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This class use to create a verifiable presentation.
 * <p>
 * A verifiable presentation expresses data from one or more credentials, and is packaged in
 * such a way that the authorship of the data is verifiable.
 * <p>
 * This object must be signed by the owner of the credential.
 * And you can send a specific verifier.
 * <p>
 * The verifier can verify the authenticity of the presentation and credentials,
 * and also verify that the owner possesses the credential
 */
public class Presentation implements ConvertJwt {

    private final static int EXP_DURATION = 5 * 60;  // seconds
    public static final String DEFAULT_TYPE = "PRESENTATION";

    private IssuerDid issuerDid;
    private List<String> types;
    private List<String> credentials;
    private String nonce;
    private String jti;

    public Presentation(IssuerDid issuerDid) {
        this.issuerDid = issuerDid;
        this.credentials = new ArrayList<>();
        this.types = new ArrayList<>();
    }

    /**
     * Add the credential
     *
     * @param claim the credential signed by issuer, the string is the encoded jwt
     *              {@linkplain DidKeyHolder#sign(Jwt)}
     */
    public void addCredential(String claim) {
        credentials.add(claim);
        Credential credential = Credential.valueOf(claim);
        List<String> credentialTypes = credential.getTypes();
        credentialTypes.remove(Credential.DEFAULT_TYPE);
        this.types.addAll(credentialTypes);
    }

    /**
     * Set the list of credential
     *
     * @param credentials the list of credential
     */
    public void setCredentials(List<String> credentials) {
        this.types.clear();
        for (String c : credentials) {
            addCredential(c);
        }
    }

    /**
     * Set a unique identifier for the presentation (Optional)
     *
     * @param nonce : the string object
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * Set a unique identifier for the JWT
     *
     * @param jti : the string object
     */
    public void setJti(String jti) {
        this.jti = jti;
    }


    public String getDid() {
        return issuerDid.getDid();
    }

    public String getKeyId() {
        return issuerDid.getKeyId();
    }

    public String getAlgorithm() {
        return issuerDid.getAlgorithm();
    }

    public List<String> getTypes() {
        List<String> result = new ArrayList<>(this.types);
        result.add(0, DEFAULT_TYPE);
        return result;
    }

    public String getNonce() {
        return nonce;
    }

    public String getJti() {
        return jti;
    }

    @Override
    public int getDuration() {
        return EXP_DURATION;
    }

    @Override
    public Jwt buildJwt(Date issued, Date expiration) {
        String kid = issuerDid.getDid() + "#" + issuerDid.getKeyId();
        return new Jwt.Builder()
                .alg(issuerDid.getAlgorithm())
                .kid(kid)
                .iss(issuerDid.getDid())
                .iat(issued)
                .exp(expiration)
                .type(getTypes())
                .credential(credentials)
                .nonce(nonce)
                .jti(jti)
                .build();
    }

    /**
     * Returns the presentation object representation of the String argument.
     *
     * @param encodedJwt the String returned by calling {@linkplain DidKeyHolder#sign(Jwt)}
     * @return the presentation object
     */
    public static Presentation valueOf(String encodedJwt) {
        return valueOf(Jwt.decode(encodedJwt));
    }

    /**
     * Returns the presentation object representation of the Jwt argument.
     *
     * @param jwt the JWT with properties of the Presentation object
     * @return the presentation object
     * @see Presentation#buildJwt(Date, Date)
     */
    public static Presentation valueOf(Jwt jwt) {
        Payload payload = jwt.getPayload();
        IssuerDid issuerDid = IssuerDid.valueOf(jwt);
        return new Builder(issuerDid)
                .credentials(payload.getCredential())
                .nonce(payload.getNonce())
                .build();
    }

    public static final class Builder {
        private IssuerDid.Builder issuerBuilder;
        private IssuerDid issuerDid;
        private List<String> credentials;
        private String nonce;

        public Builder() {
            this.issuerBuilder = new IssuerDid.Builder();
        }

        public Builder(IssuerDid issuerDid) {
            this();
            this.issuerDid = issuerDid;
        }

        public Builder didKeyHolder(DidKeyHolder keyHolder) {
            this.issuerBuilder.algorithm(keyHolder.getType().getName())
                    .keyId(keyHolder.getKeyId())
                    .did(keyHolder.getDid());
            return this;
        }

        public Builder algorithm(String algorithm) {
            this.issuerBuilder.algorithm(algorithm);
            return this;
        }

        public Builder keyId(String algorithm) {
            this.issuerBuilder.keyId(algorithm);
            return this;
        }

        public Builder did(String did) {
            this.issuerBuilder.did(did);
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder credentials(List<String> val) {
            credentials = val;
            return this;
        }

        public Presentation build() {
            if (issuerDid == null) {
                issuerDid = issuerBuilder.build();
            }
            IssuerDid.Builder.checkArgument(issuerDid, "issuerDid not found");

            Presentation presentation = new Presentation(this.issuerDid);
            presentation.nonce = nonce;
            if (credentials != null) {
                presentation.setCredentials(credentials);
            }

            return presentation;
        }
    }

    public IssuerDid getIssuerDid() {
        return issuerDid;
    }

    public List<String> getCredentials() {
        return credentials;
    }

    @Override
    public String toString() {
        return "Presentation{" +
                "issuerDid=" + issuerDid +
                ", types=" + types +
                ", credentials=" + credentials +
                ", nonce='" + nonce + '\'' +
                ", jti='" + jti + '\'' +
                '}';
    }
}
