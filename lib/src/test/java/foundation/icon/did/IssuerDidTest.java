package foundation.icon.did;


import foundation.icon.did.core.*;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.jwt.IssuerDid;
import foundation.icon.did.jwt.Jwt;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

class IssuerDidTest {

    private static Logger logger = LoggerFactory.getLogger(IssuerDidTest.class);

    @Test
    void testCreate() {
        String keyId = "key1";
        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;
        IssuerDid issuerDid = new IssuerDid.Builder()
                .did(did)
                .algorithm(type.getName())
                .keyId(keyId)
                .build();

        logger.debug("issuerDid: {}", issuerDid);

        Assertions.assertEquals(keyId, issuerDid.getKeyId());
        Assertions.assertEquals(did, issuerDid.getDid());
        Assertions.assertEquals(type.getName(), issuerDid.getAlgorithm());
    }

    @Test
    void testParse() throws Exception {
        String keyId = "key1";
        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(type);
        PrivateKey priKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_ES256));

        IssuerDid issuerDid = new IssuerDid.Builder()
                .did(did)
                .algorithm(type.getName())
                .keyId(keyId)
                .build();

        logger.debug("issuerDid: {}", issuerDid);

        String jwt = issuerDid.buildJwt().sign(priKey);

        logger.debug("buildJwt: {}", jwt);

        IssuerDid parseIssuerDid = IssuerDid.valueOf(jwt);

        logger.debug("parse IssuerDid: {}", parseIssuerDid);

        Assertions.assertEquals(keyId, parseIssuerDid.getKeyId());
        Assertions.assertEquals(did, parseIssuerDid.getDid());
        Assertions.assertEquals(type.getName(), parseIssuerDid.getAlgorithm());
    }

    @Test
    void testES256Compact() throws Exception {
        String keyId = "key1";
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(type);
        PublicKey pubKey = algorithm.byteToPublicKey(EncodeType.HEX.decode(TestKeys.PUBLIC_KEY_ES256));
        PrivateKey priKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_ES256));

        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        IssuerDid issuerDid = new IssuerDid.Builder()
                .did(did)
                .keyId(keyId)
                .algorithm(type.getName())
                .build();


        long issuedTimestamp = 1545208842000L;
        Date issued = new Date(issuedTimestamp);
        long duration = issuerDid.getDuration() * 1000L; // to milliseconds
        Date expiration = new Date(issuedTimestamp + duration);

        String jwt = issuerDid.buildJwt(issued, expiration).sign(priKey);
        logger.debug("buildJwt: {}", jwt);

        Jwt didJwt = Jwt.decode(jwt);

        Assertions.assertFalse(didJwt.verify(pubKey).isSuccess());
        Assertions.assertEquals(PropertyName.ALGO_KEY_ECDSA, didJwt.getHeader().getAlg());
        Assertions.assertEquals(did + "#" + keyId, didJwt.getHeader().getKid());
        Assertions.assertEquals(issued, didJwt.getPayload().getIat());
        Assertions.assertEquals(expiration, didJwt.getPayload().getExp());

    }

    @Test
    void testRS256Compact() throws Exception {
        String keyId = "key1";
        AlgorithmProvider.Type type = AlgorithmProvider.Type.RS256;
        Algorithm algorithm = AlgorithmProvider.create(type);
        PublicKey publicKey = algorithm.byteToPublicKey(EncodeType.HEX.decode(TestKeys.PUBLIC_KEY_RS256));
        PrivateKey priKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_RS256));

        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        IssuerDid issuerDid = new IssuerDid.Builder()
                .did(did)
                .keyId(keyId)
                .algorithm(type.getName())
                .build();

        long issuedTimestamp = 1545208842000L;
        Date issued = new Date(issuedTimestamp);
        long duration = issuerDid.getDuration() * 1000L;  // to milliseconds
        Date expiration = new Date(issuedTimestamp + duration);

        String jwt = issuerDid.buildJwt(issued, expiration).sign(priKey);
        logger.debug("buildJwt: {}", jwt);

        Jwt didJwt = Jwt.decode(jwt);
        Assertions.assertFalse(didJwt.verify(publicKey).isSuccess());
        Assertions.assertEquals(PropertyName.ALGO_KEY_RSA, didJwt.getHeader().getAlg());
        Assertions.assertEquals(did + "#" + keyId, didJwt.getHeader().getKid());
        Assertions.assertEquals(issued, didJwt.getPayload().getIat());
        Assertions.assertEquals(expiration, didJwt.getPayload().getExp());

    }

}
