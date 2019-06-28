package foundation.icon.did.core;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

public class AlgorithmTest {

    private final static Logger logger = LoggerFactory.getLogger(AlgorithmTest.class);

    byte[] message;

    @BeforeEach
    void setUp() {
        message = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgjaG9sZGVyIn0=.eyJjcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2phWE56ZFdWeUluMC5leUpqYkdGcGJTSTZleUpGYldGcGJDSTZJbUZoWVVCcFkyOXVMbVp2ZFc1a1lYUnBiMjRpZlN3aVpYaHdJam94TlRRM09ESXdNemcyTENKcFlYUWlPakUxTkRjM016TTVPRFlzSW1semN5STZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2lMQ0p1YjI1alpTSTZJakF6TURjeFpqSmtMVGhpWlRBdE5EQXhOUzA0WTJJNExUZzRZVEkzTTJGaVpXWTJOaUlzSW5OMVlpSTZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2lMQ0owZVhCbElqcGJJa1Z0WVdsc0lsMTkiXSwiZXhwIjoxNTQ1MjA5MTQyLCJpYXQiOjE1NDUyMDg4NDIsImlzcyI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgiLCJub25jZSI6IjZhNDFiOGE0LWQxOGQtNGUzMS1iNWY4LWYzOWIxNWRiNTgyNyIsInR5cGUiOlsiUFJFU0VOVEFUSU9OIiwiRW1haWwiXX0=".getBytes(StandardCharsets.UTF_8);
    }

    @RepeatedTest(100)
    void testES256K() throws Exception {
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
        KeyProvider keyProvider = algorithm.generateKeyProvider("key1");
        byte[] signature = algorithm.sign(keyProvider.getPrivateKey(), message);
        logger.debug("message:{}", Hex.toHexString(message));
        logger.debug("signature:{}", Hex.toHexString(signature));
        ECPublicKey ecPublicKey = (ECPublicKey) keyProvider.getPublicKey();
        logger.debug("publicKey:{}", Hex.toHexString(ecPublicKey.getQ().getEncoded(false)));
        boolean verify = algorithm.verify(keyProvider.getPublicKey(), message, signature);
        Assertions.assertTrue(verify);
    }

    @Test
    void testRS256() throws Exception {
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.RS256);
        KeyProvider keyProvider = algorithm.generateKeyProvider("key1");
        byte[] signature = algorithm.sign(keyProvider.getPrivateKey(), message);
        boolean verify = algorithm.verify(keyProvider.getPublicKey(), message, signature);
        Assertions.assertTrue(verify);
    }

    @RepeatedTest(100)
    void testES256() throws Exception {
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256);
        KeyProvider keyProvider = algorithm.generateKeyProvider("key1");
        byte[] signature = algorithm.sign(keyProvider.getPrivateKey(), message);
        boolean verify = algorithm.verify(keyProvider.getPublicKey(), message, signature);
        Assertions.assertTrue(verify);
    }

}
