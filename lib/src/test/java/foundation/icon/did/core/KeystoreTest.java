package foundation.icon.did.core;

import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.exceptions.KeyPairException;
import foundation.icon.did.exceptions.KeystoreException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

public class KeystoreTest {

    private final String DID = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08";
    private final String FILE_NAME = DID + ".json";
    private final String PASSWORD = "ssw0rd";

    @Test
    void testES256() throws AlgorithmException, IOException, KeystoreException, KeyPairException {
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256);
        KeyProvider keyProvider = algorithm.generateKeyProvider("key1");
        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(DID)
                .build();

        Keystore.storeDidKeyHolder(PASSWORD, didKeyHolder, FILE_NAME);
        DidKeyHolder load = Keystore.loadDidKeyHolder(PASSWORD, new File(FILE_NAME));
        assertEquals(didKeyHolder, load);
    }

    @Test
    void testRS256() throws AlgorithmException, IOException, KeystoreException, KeyPairException {
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.RS256);
        KeyProvider keyProvider = algorithm.generateKeyProvider("key1");
        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(DID)
                .build();
        Keystore.storeDidKeyHolder(PASSWORD, didKeyHolder, FILE_NAME);
        DidKeyHolder load = Keystore.loadDidKeyHolder(PASSWORD, new File(FILE_NAME));
        assertEquals(didKeyHolder, load);
    }

    @Test
    void testES256K() throws AlgorithmException, IOException, KeystoreException, KeyPairException {
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
        KeyProvider keyProvider = algorithm.generateKeyProvider("key1");
        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(DID)
                .build();
        Keystore.storeDidKeyHolder(PASSWORD, didKeyHolder, FILE_NAME);
        DidKeyHolder load = Keystore.loadDidKeyHolder(PASSWORD, new File(FILE_NAME));
        assertEquals(didKeyHolder, load);
    }

    private void assertEquals(DidKeyHolder expected, DidKeyHolder actual) {
        Assertions.assertEquals(DID, actual.getDid());
        Assertions.assertEquals(expected.getKeyId(), actual.getKeyId());
        Assertions.assertEquals(expected.getType(), actual.getType());
        Algorithm algorithm = AlgorithmProvider.create(expected.getType());
        Assertions.assertArrayEquals(algorithm.privateKeyToByte(expected.getPrivateKey()),
                algorithm.privateKeyToByte(actual.getPrivateKey()));
    }
}
