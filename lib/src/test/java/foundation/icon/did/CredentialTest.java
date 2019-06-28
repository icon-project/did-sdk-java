package foundation.icon.did;

import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.jwt.Jwt;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.util.Arrays;
import java.util.stream.Collectors;

public class CredentialTest {

    private static Logger logger = LoggerFactory.getLogger(CredentialTest.class);

    @Test
    void testBuildJwt() throws Exception {

        String keyId = TestKeys.ISSUER_KEY_ID;
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(type);
        PrivateKey priKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_ES256));

        String did = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        Credential credential = new Credential.Builder()
                .algorithm(type.getName())
                .keyId(keyId)
                .did(did)
                .build();

        Assertions.assertEquals(did, credential.getIssuerDid().getDid());

        String owner = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";

        credential.setTargetDid(owner);
        credential.addClaim("email", "aaa@icon.foundation");
        String jwt = credential.buildJwt().sign(priKey);
        logger.debug("jwt : {}", jwt);
    }

    @Test
    void testDecode() throws Exception {
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(type);
        PrivateKey priKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(TestKeys.PRIVATE_KEY_ES256));
        String encodedJwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgjaXNzdWVyIn0=.eyJjbGFpbSI6eyJFbWFpbCI6ImFhYUBpY29uLmZvdW5kYXRpb24ifSwiZXhwIjoxNTQ3ODIwMzg2LCJpYXQiOjE1NDc3MzM5ODYsImlzcyI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgiLCJub25jZSI6IjAzMDcxZjJkLThiZTAtNDAxNS04Y2I4LTg4YTI3M2FiZWY2NiIsInN1YiI6ImRpZDppY29uOjAwMDA5NjFiNmNkNjQyNTNmYjI4YzliMGQzZDIyNGJlNWY5YjE4ZDQ5ZjAxZGEzOTBmMDgiLCJ0eXBlIjpbIkNSRURFTlRJQUwiLCJFbWFpbCJdfQ==";
        Jwt decode = Jwt.decode(encodedJwt);
        Credential credential = Credential.valueOf(decode);
        String jwt = credential.buildJwt(decode.getPayload().getIat(), decode.getPayload().getExp()).sign(priKey);
        String actualJwt = String.join(".", Arrays.asList(jwt.split("\\.")).stream().limit(2).collect(Collectors.toList()));
        Assertions.assertEquals(encodedJwt, actualJwt);
    }
}
