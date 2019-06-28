package foundation.icon.did;


import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.jwt.ConvertJwt;
import foundation.icon.did.jwt.IssuerDid;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.jwt.Payload;

import java.util.*;

/**
 * This class to create a verifiable credential, which can be used to express information that a credential represents.
 * (for example, a city government, national agency, or identification number)
 * <p>
 * For credential to be verifiable, proof mechanism use Json Web Token.
 * You can generate a complete JWT (with Signature) by calling {@linkplain DidKeyHolder#sign(Jwt)}.
 * <p>
 * A credential is a set of one or more claims.
 * It might also include metadata to describe properties of the credential, such as the issuer,
 * the expiry time, the issued time, an algorithm for verification, and so on.
 * <p>
 * These claims and metadata must be signed by the issuer.
 * After that, you can generate {@linkplain Presentation presentation}.
 */
public class Credential implements ConvertJwt {

    private int expDuration = 24 * 60 * 60;  // seconds
    public static final String DEFAULT_TYPE = "CREDENTIAL";

    private IssuerDid issuerDid;
    private String targetDid;
    private Map<String, Object> claim;
    private String nonce;
    private String jti;

    public Credential(IssuerDid issuerDid) {
        this.issuerDid = issuerDid;
        claim = new HashMap<>();
    }

    /**
     * Set the did of the owner that holds the credential.
     *
     * @param did : the did
     */
    public void setTargetDid(String did) {
        this.targetDid = did;
    }

    /**
     * Add the information that express the owner's credential.
     *
     * @param type  : the type of claim (email, phone, gender)
     * @param value : the value of claim (abc@abc.com, 01012345678, M)
     */
    public void addClaim(String type, String value) {
        claim.put(type, value);
    }

    /**
     * Set the information that express the owner's credentials.
     *
     * @param claim : the map of claim  {"Email":"aaa@icon.foundation"}
     */
    public void setClaim(Map<String, Object> claim) {
        this.claim = claim;
    }

    /**
     * Set a unique identifier for the credential. (Optional)
     *
     * @param nonce : the string object
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * Set a unique identifier for the JWT.
     *
     * @param jti : the string object
     */
    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getTargetDid() {
        return targetDid;
    }

    public IssuerDid getIssuerDid() {
        return issuerDid;
    }

    public Map<String, Object> getClaim() {
        return claim;
    }

    public List<String> getTypes() {
        ArrayList<String> types = new ArrayList<>(claim.keySet());
        types.add(0, DEFAULT_TYPE);
        return types;
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

    public String getNonce() {
        return nonce;
    }

    public String getJti() {
        return jti;
    }

    @Override
    public int getDuration() {
        return expDuration;
    }

    @Override
    public Jwt buildJwt(Date issued, Date expiration) {
        String kid = issuerDid.getDid() + "#" + issuerDid.getKeyId();
        return new Jwt.Builder()
                .alg(issuerDid.getAlgorithm())
                .kid(kid)
                .sub(targetDid)
                .iss(issuerDid.getDid())
                .iat(issued)
                .exp(expiration)
                .type(getTypes())
                .claim(claim)
                .nonce(nonce)
                .jti(jti)
                .build();
    }

    /**
     * Returns the credential object representation of the String argument.
     *
     * @param encodedJwt the String returned by calling {@linkplain DidKeyHolder#sign(Jwt)}
     * @return the credential object
     */
    public static Credential valueOf(String encodedJwt) {
        return valueOf(Jwt.decode(encodedJwt));
    }


    /**
     * Returns the credential object representation of the Jwt argument.
     *
     * @param jwt the JWT with properties of the Credential object
     * @return the credential object
     * @see Credential#buildJwt(Date, Date)
     */
    public static Credential valueOf(Jwt jwt) {
        Payload payload = jwt.getPayload();
        IssuerDid issuerDid = IssuerDid.valueOf(jwt);
        return new Builder(issuerDid)
                .targetDid(payload.getSub())
                .claim(payload.getClaim())
                .nonce(jwt.getPayload().getNonce())
                .build();
    }

    public static final class Builder {
        private IssuerDid.Builder issuerBuilder;
        private IssuerDid issuerDid;

        private String targetDid;
        private Map<String, Object> claim;
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

        public Builder targetDid(String val) {
            targetDid = val;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder claim(Map<String, Object> val) {
            claim = val;
            return this;
        }

        public Credential build() {
            if (issuerDid == null) {
                issuerDid = issuerBuilder.build();
            }
            IssuerDid.Builder.checkArgument(issuerDid, "issuerDid not found");

            Credential credential = new Credential(issuerDid);
            credential.targetDid = this.targetDid;
            credential.nonce = this.nonce;
            if (this.claim != null) credential.claim = this.claim;
            return credential;
        }
    }

    @Override
    public String toString() {
        return "Credential{" +
                "issuerDid=" + issuerDid +
                ", targetDid='" + targetDid + '\'' +
                ", claim=" + claim +
                ", nonce='" + nonce + '\'' +
                ", jti='" + jti + '\'' +
                '}';
    }
}
