package foundation.icon.did.jwt;

import com.google.gson.Gson;
import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.document.Converters;
import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.exceptions.JwtException;
import okio.ByteString;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class Jwt {

    private Header header;
    private Payload payload;
    private String[] encodedToken; // [0]:header, [1]:payload, [2]:signature

    private Jwt(Header header, Payload payload, String[] encodedToken) {
        this.header = header;
        this.payload = payload;
        this.encodedToken = encodedToken;
    }

    private String encode() {
        Gson gson = Converters.gson();
        String b64Header = encodeBase64Url(gson.toJson(header).getBytes(StandardCharsets.UTF_8));
        String b64Payload = encodeBase64Url(gson.toJson(payload).getBytes(StandardCharsets.UTF_8));
        return b64Header + "." + b64Payload;
    }

    public String sign(PrivateKey privateKey) throws AlgorithmException {
        String content = encode();
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.fromName(header.getAlg()));
        byte[] bSignature = algorithm.sign(privateKey, content.getBytes(StandardCharsets.UTF_8));
        String b64Signature = encodeBase64Url(bSignature);
        return content + "." + b64Signature;
    }

    public String compact() {
        return encode() + ".";
    }

    public VerifyResult verify(PublicKey publicKey) throws AlgorithmException {
        if (encodedToken == null || encodedToken.length != 3) throw new JwtException("A signature is required for verify");
        String content = String.join(".", Arrays.copyOfRange(encodedToken, 0, 2));
        byte[] bSignature = ByteString.decodeBase64(encodedToken[2]).toByteArray();

        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.fromName(header.getAlg()));
        boolean isVerify = algorithm.verify(publicKey, content.getBytes(StandardCharsets.UTF_8), bSignature);
        if (!isVerify) {
            return new VerifyResult(false, "JWT signature does not match.");
        }
        return verify();
    }

    // check expired
    public VerifyResult verify() {
        final Date now = new Date();
        Date exp = getPayload().getExp();
        if (exp != null && now.after(exp)) {
            return new VerifyResult(false, "JWT signature does not match.");
        }
        return new VerifyResult(true, null);
    }


    public static Jwt decode(String jwt) {
        String[] jwtParts = jwt.split("\\.");
        if (!(jwtParts.length == 2 || jwtParts.length == 3))
            throw new JwtException("JWT strings must contain exactly 2 peroid characters.");

        byte[] decodedHeader = ByteString.decodeBase64(jwtParts[0]).toByteArray();
        byte[] decodedPayload = ByteString.decodeBase64(jwtParts[1]).toByteArray();

        Gson gson = Converters.gson();
        Header header = gson.fromJson(new String(decodedHeader), Header.class);
        Payload payload = gson.fromJson(new String(decodedPayload), Payload.class);
        return new Jwt(header, payload, jwtParts);
    }

    public Header getHeader() {
        return header;
    }

    public Payload getPayload() {
        return payload;
    }

    public String getSignature() {
        if (encodedToken != null && encodedToken.length == 3)
            return encodedToken[2];
        return null;
    }

    public String[] getEncodedToken() {
        return encodedToken;
    }

    private String encodeBase64Url(byte[] data) {
        return ByteString.of(data).base64Url();
    }

    public class VerifyResult {
        Boolean success;
        String failMessage;

        VerifyResult(Boolean success, String failMessage) {
            this.success = success;
            this.failMessage = failMessage;
        }

        public Boolean isSuccess() {
            return success;
        }

        public String getFailMessage() {
            return failMessage;
        }

        @Override
        public String toString() {
            return "VerifyResult{" +
                    "success=" + success +
                    ", failMessage='" + failMessage + '\'' +
                    '}';
        }
    }


    public static final class Builder {
        // header
        private String alg;
        private String kid;
        // payload
        private Payload.Builder payloadBuilder;
        private String[] encodedToken; // [0]:header, [1]:payload, [2]:signature

        public Builder() {
            payloadBuilder = new Payload.Builder();
        }

        public Builder encodedToken(String[] encodedToken) {
            this.encodedToken = encodedToken;
            return this;
        }

        public Builder alg(String alg) {
            this.alg = alg;
            return this;
        }

        public Builder kid(String kid) {
            this.kid = kid;
            return this;
        }

        public Builder type(List<String> type) {
            payloadBuilder.type(type);
            return this;
        }

        public Builder type(String type) {
            payloadBuilder.type(type);
            return this;
        }

        public Builder iss(String iss) {
            payloadBuilder.iss(iss);
            return this;
        }

        public Builder sub(String sub) {
            payloadBuilder.sub(sub);
            return this;
        }

        public Builder iat(Date iat) {
            payloadBuilder.iat(iat);
            return this;
        }

        public Builder exp(Date exp) {
            payloadBuilder.exp(exp);
            return this;
        }

        public Builder claim(Map<String, Object> claim) {
            payloadBuilder.claim(claim);
            return this;
        }

        public Builder credential(List<String> credential) {
            payloadBuilder.credential(credential);
            return this;
        }

        public Builder nonce(String nonce) {
            payloadBuilder.nonce(nonce);
            return this;
        }

        public Builder jti(String jti) {
            payloadBuilder.jti(jti);
            return this;
        }

        public Builder put(String name, Object value) {
            payloadBuilder.put(name, value);
            return this;
        }

        public Builder addTimeClaimKey(String key) {
            payloadBuilder.addTimeClaimKey(key);
            return this;
        }

        public Jwt build() {
            if (encodedToken != null) {
                if (!(encodedToken.length == 2 || encodedToken.length == 3))
                    throw new JwtException("JWT strings must contain exactly 2 peroid characters.");
            }

            Header header = new Header.Builder()
                    .alg(this.alg)
                    .kid(this.kid)
                    .build();

            return new Jwt(header, payloadBuilder.build(), encodedToken);
        }
    }

    @Override
    public String toString() {
        return "Jwt{" +
                "header=" + header +
                ", payload=" + payload +
                '}';
    }
}
