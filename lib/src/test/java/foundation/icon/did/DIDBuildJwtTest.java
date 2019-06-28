package foundation.icon.did;

import foundation.icon.did.core.*;
import foundation.icon.did.document.Converters;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.document.PublicKeyProperty;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.score.ScoreParameter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;

import static foundation.icon.did.TestKeys.TEMP_DID;

public class DIDBuildJwtTest {

    private static Logger logger = LoggerFactory.getLogger(DIDBuildJwtTest.class);

    @Test
    void testBuildCreateJwt() throws Exception {
        String keyId = "key1";
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(type);
        PublicKey publicKey = algorithm.byteToPublicKey(EncodeType.HEX.decode(TestKeys.PUBLIC_KEY_ES256));
        PrivateKey privateKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_ES256));
        KeyProvider keyProvider = new KeyProvider.Builder()
                .keyId(keyId)
                .publicKey(publicKey)
                .privateKey(privateKey)
                .type(type)
                .build();


        String json = ScoreParameter.create(keyProvider, EncodeType.HEX);
        logger.debug("json: {}", json);
        PublicKeyProperty publicKeyProperty = Converters.gson().fromJson(json, PublicKeyProperty.class);
        Assertions.assertEquals(keyId, publicKeyProperty.getId());
        Assertions.assertEquals(type.getIdentifier(), publicKeyProperty.getType().get(0));
        Assertions.assertArrayEquals(algorithm.publicKeyToByte(publicKey), algorithm.publicKeyToByte(publicKeyProperty.getPublicKey()));
    }

    @Test
    void testBuildAddKeyJwt() throws Exception {

        // authentication public / private key
        String authKeyId = "key1";
        AlgorithmProvider.Type authType = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(authType);
        PrivateKey authPrivateKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_ES256));
        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder()
                .did(TEMP_DID)
                .keyId(authKeyId)
                .privateKey(authPrivateKey)
                .type(authType)
                .build();

        // add public / private key
        String key2 = "key2";
        AlgorithmProvider.Type type2 = AlgorithmProvider.Type.RS256;
        algorithm = AlgorithmProvider.create(type2);
        PublicKey publicKey = algorithm.byteToPublicKey(EncodeType.HEX.decode(TestKeys.PUBLIC_KEY_RS256));
        PrivateKey privateKey2 = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_RS256));
        KeyProvider keyProvider2 = new KeyProvider.Builder()
                .keyId(key2)
                .publicKey(publicKey)
                .privateKey(privateKey2)
                .type(type2)
                .build();


        String json = ScoreParameter.create(keyProvider2, EncodeType.BASE64);
        logger.debug("json: {}", json);

        Jwt addJwt = ScoreParameter.addKey(didKeyHolder, keyProvider2, EncodeType.BASE64);
        logger.debug("encodedJwt: {}", didKeyHolder.sign(addJwt));
    }

    @Test
    void testBuildRevokeKeyJwt() throws Exception {
        String authKeyId = "key1";
        AlgorithmProvider.Type authType = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(authType);
        PrivateKey authPrivateKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_ES256));

        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder()
                .did(TEMP_DID)
                .keyId(authKeyId)
                .privateKey(authPrivateKey)
                .type(authType)
                .build();

        Jwt jwt = ScoreParameter.revokeKey(didKeyHolder, "key2");
        logger.debug("encodedJwt: {}", didKeyHolder.sign(jwt));
    }
}
