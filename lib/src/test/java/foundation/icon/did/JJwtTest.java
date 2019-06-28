package foundation.icon.did;


import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.jwt.IssuerDid;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

public class JJwtTest {

    private static Logger logger = LoggerFactory.getLogger(JJwtTest.class);

    @Test
    void testCreate() {
        String keyId = "key1";
        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        String kid = did + "#" + keyId;

        long duration = 5 * 60;
        Date iat = new Date();
        Date exp = new Date(iat.getTime() + duration * 1000L);
        String encodedJwt = Jwts.builder()
                .setHeaderParam("alg", "ES256")
                .setHeaderParam("kid", kid)
                .setIssuer(did)
                .setIssuedAt(iat)
                .setExpiration(exp)
                .compact();

        logger.debug("encodedJwt: {}", encodedJwt);
        try {
            Jwt<Header, Claims> jwt = Jwts.parser()
                    .parseClaimsJwt(encodedJwt);
            logger.debug("decode jwt: {}", jwt);

        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
    }

    @Test
    void testExpiredJwt() throws Exception {
        String keyId = "key1";
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256);
        PublicKey pubKey = algorithm.byteToPublicKey(Hex.decode("3059301306072a8648ce3d020106082a8648ce3d030107034200049548b1aedbb7b812ef2412c7922cde2f9b358939877410cce4a6777ec1b651f17b5a169be5d175d5f801069653a429ccf42c7e6ff9223ffee957dbf8ff5de917"));
        PrivateKey priKey = algorithm.byteToPrivateKey(Hex.decode("308193020100301306072a8648ce3d020106082a8648ce3d03010704793077020101042059e7f78342999fc71dc12e63e6747d0a1c9059d3cf1140a2af9a1b7eb4e3e0dda00a06082a8648ce3d030107a144034200049548b1aedbb7b812ef2412c7922cde2f9b358939877410cce4a6777ec1b651f17b5a169be5d175d5f801069653a429ccf42c7e6ff9223ffee957dbf8ff5de917"));

        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        IssuerDid issuerDid = new IssuerDid.Builder()
                .did(did)
                .algorithm(algorithm.getType().getName())
                .keyId(keyId)
                .build();


        // epoch timestamp 를 사용해야함
        Date issued = new Date(1547627598000L);
        Date expiration = new Date(1547627598000L);

        String encodedJwt = issuerDid.buildJwt(issued, expiration).sign(priKey);
        logger.debug("encodedJwt: {}", encodedJwt);

        try {
            io.jsonwebtoken.Jws jwtparser = Jwts.parser()
                    .setSigningKey(pubKey)
                    .parseClaimsJws(encodedJwt);
            logger.debug("jwt parser:{}", jwtparser);
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
    }
}
