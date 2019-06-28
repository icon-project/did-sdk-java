package foundation.icon.did.core;


import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.jwt.IssuerDid;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;


public class KeyProviderTest {

    private static Logger logger = LoggerFactory.getLogger(KeyProviderTest.class);

    public File tempDir;

    private static File createTempDir() throws Exception {
        return Files.createTempDirectory(
                "testkeys").toFile();
    }

    @BeforeEach
    void setUp() throws Exception {
        tempDir = createTempDir();
    }

    @Test
    void testRS256Create() throws Exception {
        String keyId = "key-1";
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.RS256);
        KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);

        logger.debug("didKeyHolder {}", keyProvider);
        Assertions.assertEquals(keyId, keyProvider.getKeyId());
        Assertions.assertEquals(AlgorithmProvider.Type.RS256, keyProvider.getType());
    }

    @Test
    void testES256Create() throws Exception {
        String keyId = "key-1";
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256);
        KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);

        logger.debug("didKeyHolder {}", keyProvider);
        Assertions.assertEquals(keyId, keyProvider.getKeyId());
        Assertions.assertEquals(AlgorithmProvider.Type.ES256, keyProvider.getType());
    }

    @Test
    void testRS256PublicKey() throws Exception {
        String keyId = "rs256";
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.RS256);
        KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);
        System.out.println(keyProvider.getPublicKey());
        System.out.println(Hex.toHexString(keyProvider.getPublicKey().getEncoded()));

        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyProvider.getPrivateKey();
        RSAPublicKeySpec spec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = factory.generatePublic(spec);
        System.out.println(publicKey);
        System.out.println(Hex.toHexString(publicKey.getEncoded()));

        byte[] message = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgjaG9sZGVyIn0=.eyJjcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2phWE56ZFdWeUluMC5leUpqYkdGcGJTSTZleUpGYldGcGJDSTZJbUZoWVVCcFkyOXVMbVp2ZFc1a1lYUnBiMjRpZlN3aVpYaHdJam94TlRRM09ESXdNemcyTENKcFlYUWlPakUxTkRjM016TTVPRFlzSW1semN5STZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2lMQ0p1YjI1alpTSTZJakF6TURjeFpqSmtMVGhpWlRBdE5EQXhOUzA0WTJJNExUZzRZVEkzTTJGaVpXWTJOaUlzSW5OMVlpSTZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2lMQ0owZVhCbElqcGJJa1Z0WVdsc0lsMTkiXSwiZXhwIjoxNTQ1MjA5MTQyLCJpYXQiOjE1NDUyMDg4NDIsImlzcyI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgiLCJub25jZSI6IjZhNDFiOGE0LWQxOGQtNGUzMS1iNWY4LWYzOWIxNWRiNTgyNyIsInR5cGUiOlsiUFJFU0VOVEFUSU9OIiwiRW1haWwiXX0=".getBytes(StandardCharsets.UTF_8);
        byte[] signature = algorithm.sign(keyProvider.getPrivateKey(), message);
        boolean verify = algorithm.verify(publicKey, message, signature);
        System.out.println("verify:" + verify);


        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        spec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
        factory = KeyFactory.getInstance("RSA");
        publicKey = factory.generatePublic(spec);
        System.out.println(publicKey);


        IssuerDid issuerDid = new IssuerDid.Builder()
                .did(did)
                .algorithm(keyProvider.getType().getName())
                .keyId(keyProvider.getKeyId())
                .build();

        String encodedJwt = issuerDid.buildJwt().sign(keyProvider.getPrivateKey());

        try {
            io.jsonwebtoken.Jws jwtparser = Jwts.parser()
                    .setSigningKey(publicKey)
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

    @Test
    void testES256KPublicKey() throws AlgorithmException {
        String keyId = "es256k";
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
        KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);
        System.out.println(keyProvider.getPublicKey());
        byte[] pub = ((ECPublicKey) keyProvider.getPublicKey()).getQ().getEncoded(false);

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
        ECParameterSpec ecparameterSpec = new ECParameterSpec(spec.getCurve(), spec.getG(), spec.getN());

        try {
            KeyFactory fact = KeyFactory.getInstance("EC", "BC");
            PublicKey publicKey = fact.generatePublic(new ECPublicKeySpec(spec.getCurve().decodePoint(pub), ecparameterSpec));
            System.out.println(publicKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

    }
}

