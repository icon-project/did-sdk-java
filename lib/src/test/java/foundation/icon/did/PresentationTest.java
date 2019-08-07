package foundation.icon.did;

import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.jwt.IssuerDid;
import foundation.icon.did.jwt.Jwt;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class PresentationTest {

    private static Logger logger = LoggerFactory.getLogger(PresentationTest.class);

    @Test
    void testBuildJwt() throws Exception {

        String keyId = TestKeys.HOLDER_KEY_ID;
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(type);
        PrivateKey priKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_ES256));

        String rawCredential = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgjaXNzdWVyIn0.eyJjbGFpbSI6eyJFbWFpbCI6ImFhYUBpY29uLmZvdW5kYXRpb24ifSwiZXhwIjoxNTQ3ODIwMzg2LCJpYXQiOjE1NDc3MzM5ODYsImlzcyI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgiLCJub25jZSI6IjAzMDcxZjJkLThiZTAtNDAxNS04Y2I4LTg4YTI3M2FiZWY2NiIsInN1YiI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgiLCJ0eXBlIjpbIkVtYWlsIl19";
        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        String version = "1.0";
        DidKeyHolder keyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(keyId)
                .type(type)
                .privateKey(priKey)
                .build();

        Presentation presentation = new Presentation.Builder()
                .didKeyHolder(keyHolder)
                .build();
        presentation.addCredential(rawCredential);
        presentation.setNonce("6a41b8a4-d18d-4e31-b5f8-f39b15db5827");
        presentation.setVersion(version);

        long issuedTimestamp = 1545208842000L;
        Date issued = new Date(issuedTimestamp);
        long duration = presentation.getIssuerDid().getDuration() * 1000L; // to milliseconds
        Date expiration = new Date(issuedTimestamp + duration);

        Jwt didJwt = presentation.buildJwt(issued, expiration);

        String jwt = keyHolder.sign(didJwt);
        String expectedJwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgjaG9sZGVyIn0=.eyJjcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2phWE56ZFdWeUluMC5leUpqYkdGcGJTSTZleUpGYldGcGJDSTZJbUZoWVVCcFkyOXVMbVp2ZFc1a1lYUnBiMjRpZlN3aVpYaHdJam94TlRRM09ESXdNemcyTENKcFlYUWlPakUxTkRjM016TTVPRFlzSW1semN5STZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2lMQ0p1YjI1alpTSTZJakF6TURjeFpqSmtMVGhpWlRBdE5EQXhOUzA0WTJJNExUZzRZVEkzTTJGaVpXWTJOaUlzSW5OMVlpSTZJbVJwWkRwcFkyOXVPakF3TURBNU5qRmlObU5rTmpReU5UTm1Zakk0WXpsaU1HUXpaREl5TkdKbE5XWTVZakU0WkRRNVpqQXhaR0V6T1RCbU1EZ2lMQ0owZVhCbElqcGJJa1Z0WVdsc0lsMTkiXSwiZXhwIjoxNTQ1MjA5MTQyLCJpYXQiOjE1NDUyMDg4NDIsImlzcyI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgiLCJub25jZSI6IjZhNDFiOGE0LWQxOGQtNGUzMS1iNWY4LWYzOWIxNWRiNTgyNyIsInR5cGUiOlsiUFJFU0VOVEFUSU9OIiwiRW1haWwiXX0=";
        String actualJwt = String.join(".", Arrays.asList(jwt.split("\\.")).stream().limit(2).collect(Collectors.toList()));
        Assertions.assertEquals(expectedJwt, actualJwt);
    }

    @Test
    void testParse() throws Exception {
        String jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgjaG9sZGVyIn0.eyJjbGFpbXMiOlsiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbXRwWkNJNkltUnBaRHBwWTI5dU9qQXdNREE1TmpGaU5tTmtOalF5TlRObVlqSTRZemxpTUdRelpESXlOR0psTldZNVlqRTRaRFE1WmpBeFpHRXpPVEJtTURnamFYTnpkV1Z5SW4wLmV5SmpiR0ZwYlNJNmV5SkZiV0ZwYkNJNkltRmhZVUJwWTI5dUxtWnZkVzVrWVhScGIyNGlmU3dpWlhod0lqb3hOVFEzT0RJd016ZzJMQ0pwWVhRaU9qRTFORGMzTXpNNU9EWXNJbWx6Y3lJNkltUnBaRHBwWTI5dU9qQXdNREE1TmpGaU5tTmtOalF5TlRObVlqSTRZemxpTUdRelpESXlOR0psTldZNVlqRTRaRFE1WmpBeFpHRXpPVEJtTURnaUxDSnViMjVqWlNJNklqQXpNRGN4WmpKa0xUaGlaVEF0TkRBeE5TMDRZMkk0TFRnNFlUSTNNMkZpWldZMk5pSXNJbk4xWWlJNkltUnBaRHBwWTI5dU9qQXdNREE1TmpGaU5tTmtOalF5TlRObVlqSTRZemxpTUdRelpESXlOR0psTldZNVlqRTRaRFE1WmpBeFpHRXpPVEJtTURnaUxDSjBlWEJsSWpwYklrVnRZV2xzSWwxOSJdLCJleHAiOjE1NDUyMDkxNDIsImlhdCI6MTU0NTIwODg0MiwiaXNzIjoiZGlkOmljb246MDAwMDk2MWI2Y2Q2NDI1M2ZiMjhjOWIwZDNkMjI0YmU1ZjliMThkNDlmMDFkYTM5MGYwOCIsIm5vbmNlIjoiNmE0MWI4YTQtZDE4ZC00ZTMxLWI1ZjgtZjM5YjE1ZGI1ODI3IiwidHlwZSI6WyJQUkVTRU5UQVRJT04iLCJFbWFpbCJdfQ.1GfPU-0eiRmaVDOqh0v8ptLdr3AHkU8iagtOGOmpzrZ55YmnLjLuZd8qx-RSQoDJ5U0NChv1lFFigtCpAEejAw";

        Jwt didJwt = Jwt.decode(jwt);
        Presentation presentation = Presentation.valueOf(didJwt);
        logger.debug("did: {}", didJwt);
        IssuerDid issuerDid = presentation.getIssuerDid();
        String did = issuerDid.getDid();
        String keyId = issuerDid.getKeyId();
        logger.debug("did: {}", did);
        logger.debug("keyId: {}", keyId);

        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256);
        PublicKey pubKey = algorithm.byteToPublicKey(Hex.decode(TestKeys.PUBLIC_KEY_ES256));


        Jwt.VerifyResult verifyResult = didJwt.verify(pubKey);
        logger.debug("isVerify: {}", verifyResult);
        if (!verifyResult.isSuccess()) {
            return;
        }

        logger.debug("presentation: {}", presentation);

        List<String> claims = presentation.getCredentials();
        for (String verifiableClaimJwt : claims) {
            logger.debug("verifiableClaimJwt: {}", verifiableClaimJwt);
            Jwt c = Jwt.decode(verifiableClaimJwt);
            Credential verifiableClaim = Credential.valueOf(c);
            IssuerDid i = verifiableClaim.getIssuerDid();
            String iDid = i.getDid();
            String iKeyId = i.getKeyId();
            logger.debug("idid: {}", iDid);
            logger.debug("ikeyId: {}", iKeyId);

            List<String> type = verifiableClaim.getTypes();
            logger.debug("type: {}", type);
            Map<String, Object> claim = verifiableClaim.getClaim();
            logger.debug("claim: {}", claim);

            PublicKey p = algorithm.byteToPublicKey(Hex.decode(TestKeys.PUBLIC_KEY_ES256));
            verifyResult = c.verify(p);
            logger.debug("isVerify: {}", verifyResult);
        }
    }
}
