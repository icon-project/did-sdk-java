package foundation.icon.did.jwt;


import foundation.icon.did.core.DidKeyHolder;

import java.util.Date;

/**
 * This class holds DID-related information of the issuer in JWT.
 * <p>
 * We can get this information from the JWT header.
 */
public class IssuerDid implements ConvertJwt {

    private final static int EXP_DURATION = 5 * 60;  // seconds

    private String did;
    private String algorithm;
    private String keyId;

    IssuerDid(String did, String algorithm, String keyId) {
        this.did = did;
        this.algorithm = algorithm;
        this.keyId = keyId;
    }

    @Override
    public int getDuration() {
        return EXP_DURATION;
    }

    /**
     * Create a new JWT
     *
     * @param issued     토큰 발급 시간
     * @param expiration 토큰 만료 시간
     * @return a Jwt
     */
    @Override
    public Jwt buildJwt(Date issued, Date expiration) {
        String kid = did + "#" + keyId;
        return new Jwt.Builder()
                .alg(algorithm)
                .kid(kid)
                .iss(did)
                .iat(issued)
                .exp(expiration)
                .build();
    }

    /**
     * Returns the IssuerDid object representation of the String argument.
     *
     * @param encodedJwt the String returned by calling {@linkplain DidKeyHolder#sign(Jwt)}
     * @return the IssuerDid object
     */
    public static IssuerDid valueOf(String encodedJwt) {
        return valueOf(Jwt.decode(encodedJwt));
    }

    /**
     * Returns the IssuerDid object representation of the Jwt argument.
     *
     * @param jwt the JWT with properties of the Presentation object
     * @return the IssuerDid object
     * @see IssuerDid#buildJwt(Date, Date)
     */
    public static IssuerDid valueOf(Jwt jwt) {
        Header header = jwt.getHeader();
        String[] kid = header.getKid().split("#");

        return new Builder()
                .did(kid[0])
                .algorithm(header.getAlg())
                .keyId(kid[1])
                .build();
    }

    public static IssuerDid valueOf(DidKeyHolder didKeyHolder) {
        return new Builder()
                .did(didKeyHolder.getDid())
                .algorithm(didKeyHolder.getType().getName())
                .keyId(didKeyHolder.getKeyId())
                .build();
    }

    public String getDid() {
        return did;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getKeyId() {
        return keyId;
    }


    public static final class Builder {
        private String did;
        private String algorithm;
        private String keyId;

        public Builder() {
        }

        public Builder did(String did) {
            this.did = did;
            return this;
        }

        public Builder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public IssuerDid build() {
            checkArgument(did, "did not found");
            checkArgument(algorithm, "algorithm not found");
            checkArgument(keyId, "keyId not found");

            return new IssuerDid(did, algorithm, keyId);
        }

        public static <T> void checkArgument(T object, String message) {
            if (object == null) {
                throw new IllegalArgumentException(message);
            }
        }
    }

    @Override
    public String toString() {
        return "IssuerDid{" +
                "did='" + did + '\'' +
                ", algorithm='" + algorithm + '\'' +
                ", keyId='" + keyId + '\'' +
                '}';
    }

}
