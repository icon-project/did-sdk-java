package foundation.icon.did;

import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.core.KeyProvider;
import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.jwt.Header;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.jwt.Payload;
import foundation.icon.did.protocol.ClaimRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

@SuppressWarnings("Duplicates")
public class ClaimRequestTest {

    private static Logger logger = LoggerFactory.getLogger(ClaimRequestTest.class);

    @Test
    void testCredentialRequest() throws AlgorithmException {

        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
        KeyProvider keyProvider = algorithm.generateKeyProvider("key");
        String ownerDid = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        String issuerDid = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        List<String> claimTypes = Arrays.asList("email");
        List<String> claimValues = Arrays.asList("abc@icon.foundation");

        Map claims = new HashMap();
        for (int i = 0; i < claimTypes.size(); i++) {
            claims.put(claimTypes.get(i), claimValues.get(i));
        }

        Date requestDate = new Date();
        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(ownerDid)
                .build();

        ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.CREDENTIAL)
                .didKeyHolder(didKeyHolder)
                .requestDate(requestDate)
                .requestClaims(claims)
                .responseId(issuerDid)
                .build();

        String signedJwt = didKeyHolder.sign(request.getJwt());
        logger.debug("jwt : {}", signedJwt);

        ClaimRequest decodeRequest = ClaimRequest.valueOf(signedJwt);
        Map expected = request.getJwt().getPayload().getMap();
        Map actual = decodeRequest.getJwt().getPayload().getMap();
        Assertions.assertArrayEquals(expected.values().toArray(), actual.values().toArray());
        Assertions.assertArrayEquals(expected.keySet().toArray(), actual.keySet().toArray());

        // Header
        Header header = request.getJwt().getHeader();
        String kid = ownerDid + "#" + didKeyHolder.getKeyId();
        Assertions.assertEquals(kid, header.getKid());
        Assertions.assertEquals(algorithm.getType().getName(), header.getAlg());

        // Payload
        Payload payload = request.getJwt().getPayload();
        Assertions.assertEquals(ownerDid, payload.getIss());
        List<String> actualTypes = payload.getTypes();
        actualTypes.remove(0);
        Assertions.assertArrayEquals(claimTypes.toArray(), actualTypes.toArray());
        Assertions.assertEquals(claims, decodeRequest.getClaims());
        Assertions.assertEquals(requestDate.getTime() / 1000, payload.getIat().getTime() / 1000);

        Jwt.VerifyResult result = decodeRequest.verify(keyProvider.getPublicKey());
        Assertions.assertTrue(result.isSuccess());
    }

    @Test
    void testPresentationRequest() throws AlgorithmException {

        // DID 가 없으면 verify 는 어떻게?
        // credentail 과 차이점? subject 가 추가됨
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
        KeyProvider keyProvider = algorithm.generateKeyProvider("key");
        String verifierDid = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        String ownerDid = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        List<String> types = Arrays.asList("passportType", "passportNum");

        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(verifierDid)
                .build();

        Date requestDate = new Date();
        ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.PRESENTATION)
                .didKeyHolder(didKeyHolder)
                .responseId(ownerDid)
                .requestDate(requestDate)
                .requestClaimTypes(types)
                .build();

        String signedJwt = request.getJwt().sign(didKeyHolder.getPrivateKey());
        logger.debug("jwt : {}", signedJwt);

        ClaimRequest decodeRequest = ClaimRequest.valueOf(signedJwt);
        Map expected = request.getJwt().getPayload().getMap();
        Map actual = decodeRequest.getJwt().getPayload().getMap();
        Assertions.assertArrayEquals(expected.values().toArray(), actual.values().toArray());
        Assertions.assertArrayEquals(expected.keySet().toArray(), actual.keySet().toArray());

        // Header
        Header header = request.getJwt().getHeader();
        String kid = verifierDid + "#" + didKeyHolder.getKeyId();
        Assertions.assertEquals(kid, header.getKid());
        Assertions.assertEquals(algorithm.getType().getName(), header.getAlg());

        // Payload
        Payload payload = request.getJwt().getPayload();
        Assertions.assertEquals(verifierDid, payload.getIss());
        Assertions.assertEquals(ownerDid, payload.getSub());
        List<String> actualTypes = payload.getTypes();
        actualTypes.remove(0);
        Assertions.assertArrayEquals(types.toArray(), actualTypes.toArray());
        Assertions.assertEquals(requestDate.getTime() / 1000, payload.getIat().getTime() / 1000);

        Jwt.VerifyResult result = decodeRequest.verify(keyProvider.getPublicKey());
        Assertions.assertTrue(result.isSuccess());

    }

    @Test
    void testAlgNonePresentationRequest() throws AlgorithmException {

        String ownerDid = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
        List<String> types = Arrays.asList("passportType", "passportNum");

        Date requestDate = new Date();
        ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.PRESENTATION)
                .algorithm(AlgorithmProvider.Type.NONE)
                .responseId(ownerDid)
                .requestDate(requestDate)
                .requestClaimTypes(types)
                .build();

        String signedJwt = request.compact();
        logger.debug("jwt : {}", signedJwt);

        ClaimRequest decodeRequest = ClaimRequest.valueOf(signedJwt);
        Map expected = request.getJwt().getPayload().getMap();
        Map actual = decodeRequest.getJwt().getPayload().getMap();
        Assertions.assertArrayEquals(expected.values().toArray(), actual.values().toArray());
        Assertions.assertArrayEquals(expected.keySet().toArray(), actual.keySet().toArray());

        // Header
        Header header = request.getJwt().getHeader();
        Assertions.assertEquals(AlgorithmProvider.Type.NONE.getName(), header.getAlg());

        // Payload
        Payload payload = request.getJwt().getPayload();
        Assertions.assertNull(payload.getIss());
        Assertions.assertEquals(ownerDid, payload.getSub());
        List<String> actualTypes = payload.getTypes();
        actualTypes.remove(0);
        Assertions.assertArrayEquals(types.toArray(), actualTypes.toArray());
        Assertions.assertEquals(requestDate.getTime() / 1000, payload.getIat().getTime() / 1000);
    }
}
