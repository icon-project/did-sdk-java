package foundation.icon.did.protocol;

import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.jwt.Header;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.jwt.Payload;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Credential and presentation request.
 * <p>
 * This class is used when requesting a credential from an issuer or requesting a presentation from owner.
 */
public class ClaimRequest {

    public static final int DEFAULT_TYPE_POSITION = 0;
    public static final String REQ_CREDENTIAL = "REQ_CREDENTIAL";
    public static final String REQ_PRESENTATION = "REQ_PRESENTATION";

    public static final String REQUEST_CLAIM = "requestClaim";

    private Jwt jwt;

    private ClaimRequest(Jwt jwt) {
        this.jwt = jwt;
    }

    public Jwt getJwt() {
        return jwt;
    }

    public String compact() {
        return jwt.compact();
    }

    public Jwt.VerifyResult verify(PublicKey publicKey) throws AlgorithmException {
        return jwt.verify(publicKey);
    }

    public Map<String, Object> getClaims() {
        return jwt.getPayload().get(REQUEST_CLAIM, Map.class);
    }

    public List<String> getTypes() {
        return jwt.getPayload().getTypes();
    }

    public List<String> getClaimTypes() {
        List<String> types = jwt.getPayload().getTypes();
        types.remove(DEFAULT_TYPE_POSITION);
        return types;
    }

    public String getAlgorithm() {
        return jwt.getHeader().getAlg();
    }

    public String getKid() {
        return jwt.getHeader().getKid();
    }

    public String getDid() {
        return jwt.getHeader().getKid().split("#")[0];
    }

    public String getKeyId() {
        return jwt.getHeader().getKid().split("#")[1];
    }

    public Date getRequestDate() {
        return jwt.getPayload().getIat();
    }

    public String getResponseId() {
        return jwt.getPayload().getAud();
    }

    public String getRequestId() {
        return jwt.getPayload().getIss();
    }

    public String getNonce() {
        return jwt.getPayload().getNonce();
    }

    public String getVersion() { return  jwt.getPayload().getVersion(); }

    /**
     * Returns the ClaimRequest object representation of the String argument.
     *
     * @param encodedJwt the String returned by calling {@linkplain DidKeyHolder#sign(Jwt)}
     * @return the ClaimRequest object
     */
    public static ClaimRequest valueOf(String encodedJwt) {
        return valueOf(Jwt.decode(encodedJwt));
    }

    /**
     * Returns the credential object representation of the Jwt argument.
     *
     * @param jwt the JWT with properties of the ClaimRequset object
     * @return the ClaimRequest object
     * @see Builder#build()
     */
    public static ClaimRequest valueOf(Jwt jwt) {
        Payload payload = jwt.getPayload();
        Header header = jwt.getHeader();
        List<String> types = payload.getTypes();
        Type type = Type.fromValue(types.remove(0));
        String responseId = null;
        if(payload.getAud() != null) {
            responseId = payload.getAud();
        }else if(payload.getSub() != null){
            responseId = payload.getSub();
        }

        return new Builder(type)
                .algorithm(AlgorithmProvider.Type.fromName(header.getAlg()))
                .kid(header.getKid())
                .responseId(responseId)
                .requestDate(payload.getIat())
                .requestClaimTypes(types)
                .requestClaims(payload.get(REQUEST_CLAIM, Map.class))
                .nonce(payload.getNonce())
                .version(payload.getVersion())
                .encodedToken(jwt.getEncodedToken())
                .build();
    }

    public static final class Builder {
        private AlgorithmProvider.Type algorithm;
        private String kid;
        private String did;
        private String publicKeyId;
        private String responseId;
        private Type type;
        private Date requestDate;
        private List<String> claimTypes;
        private Map<String, Object> claims;
        private String[] encodedToken; // [0]:header, [1]:payload, [2]:signature
        private String nonce;
        private String jti;
        private String version;

        public Builder(Type type) {
            this.type = type;
        }

        public Builder didKeyHolder(DidKeyHolder keyHolder) {
            this.algorithm = keyHolder.getType();
            this.publicKeyId = keyHolder.getKeyId();
            this.did = keyHolder.getDid();
            return this;
        }

        public Builder algorithm(AlgorithmProvider.Type algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder kid(String kid) {
            this.kid = kid;
            if (kid != null) {
                String[] arr = kid.split("#");
                did = arr[0];
                publicKeyId = arr[1];
            }
            return this;
        }


        public Builder did(String did) {
            this.did = did;
            return this;
        }

        public Builder publicKeyId(String publicKeyId) {
            this.publicKeyId = publicKeyId;
            return this;
        }

        public Builder responseId(String responseId) {
            this.responseId = responseId;
            return this;
        }

        public Builder requestDate(Date requestDate) {
            this.requestDate = requestDate;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder jti(String jti) {
            this.jti = jti;
            return this;
        }

        public Builder version(String version) {
            this.version = version;
            return this;
        }

        public Builder requestClaimTypes(List<String> claimTypes) {
            this.claimTypes = claimTypes;
            return this;
        }

        public Builder requestClaims(Map<String, Object> claims) {
            this.claims = claims;
            if (claims != null) {
                this.claimTypes = new ArrayList<>(claims.keySet());
            }
            return this;
        }

        public Builder encodedToken(String[] encodedToken) {
            this.encodedToken = encodedToken;
            return this;
        }

        private List<String> buildTypes() {
            List<String> types = new ArrayList<>();
            types.add(this.type.getValue());
            types.addAll(this.claimTypes);
            return types;
        }

        @SuppressWarnings("Duplicates")
        public ClaimRequest build() {
            if (this.claimTypes == null) throw new IllegalArgumentException("claimTypes == null");
            if (this.responseId == null) throw new IllegalArgumentException("responseId == null");

            if (algorithm != AlgorithmProvider.Type.NONE) {
                if (this.did == null) throw new IllegalArgumentException("did == null");
                if (this.algorithm == null) throw new IllegalArgumentException("algorithm == null");
                if (this.publicKeyId == null) throw new IllegalArgumentException("publicKeyId == null");
                if (kid == null) kid = did + "#" + publicKeyId;
            } else if (this.type != Type.PRESENTATION) {
                throw new IllegalStateException("alg == \'none\' is only support when type is presentation");
            }

            if (requestDate == null) {
                requestDate = new Date();
            }

            Jwt jwt = new Jwt.Builder()
                    .alg(algorithm.getName())
                    .kid(kid)
                    .iss(did)
                    .aud(responseId)
                    .iat(requestDate)
                    .put(REQUEST_CLAIM, claims)
                    .encodedToken(encodedToken)
                    .type(buildTypes())
                    .nonce(nonce)
                    .jti(jti)
                    .version(version)
                    .build();
            return new ClaimRequest(jwt);
        }

    }

    @Override
    public String toString() {
        return "ClaimRequest{" +
                "jwt=" + jwt +
                '}';
    }

    public enum Type {

        CREDENTIAL(REQ_CREDENTIAL),
        PRESENTATION(REQ_PRESENTATION);

        private String value;

        Type(String value) {
            this.value = value;
        }

        private String getValue() {
            return this.value;
        }

        public static Type fromValue(String value) {
            if (value != null) {
                for (Type t : Type.values()) {
                    if (value.equalsIgnoreCase(t.getValue())) {
                        return t;
                    }
                }
            }
            return null;
        }
    }
}

