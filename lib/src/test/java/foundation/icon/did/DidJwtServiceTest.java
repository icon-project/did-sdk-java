package foundation.icon.did;


import foundation.icon.did.core.*;
import foundation.icon.did.document.Document;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.document.PublicKeyProperty;
import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.exceptions.KeyPairException;
import foundation.icon.did.exceptions.KeystoreException;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.score.ScoreParameter;
import foundation.icon.icx.IconService;
import foundation.icon.icx.KeyWallet;
import foundation.icon.icx.data.Address;
import foundation.icon.icx.data.Bytes;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DidJwtServiceTest {

    private static Logger logger = LoggerFactory.getLogger(DidJwtServiceTest.class);
    private final String PASSWORD = "P@ssw0rd";
    private final String FILE_NAME = "temp.json";
    private DidService didService;

    @BeforeEach
    public void setUp() throws Exception {
        BigInteger networkId = new BigInteger("3");
        IconService iconService = IconServiceFactory.createLocal();
        Address scoreAddress = new Address("cx26484cf9cb42b6eebbf537fbfe6b7df3f86c5079");

        // cx5681b1427cb3d7ca37c66dffa74e90bfb268c43d
//        BigInteger networkId = new BigInteger("2");
//        IconService iconService = IconServiceFactory.createDev();
//        Address scoreAddress = new Address("cx9a96c0dcf0567635309809d391908c32fcca5310");

        didService = new DidService(iconService, networkId, scoreAddress);
    }

    @Test
    void testGetVersion() throws IOException {
        Assertions.assertDoesNotThrow(() -> {
            String version = didService.getVersion();
            logger.debug("version:{}", version);
        });
    }

    @Test
    @Order(2)
    void testCreate() throws AlgorithmException, IOException, KeystoreException {
        KeyWallet wallet = KeyWallet.load(new Bytes(TestKeys.ICON_WALLET_PRIVATE_KEY));
        String keyId = "ES256K-key";
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
        Algorithm algorithm = AlgorithmProvider.create(type);
        KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);
        String json = ScoreParameter.create(keyProvider, EncodeType.BASE64);
        Document doc = didService.create(wallet, json);

        logger.debug("json - {}", json);
        logger.debug("DID Document - {}", doc);
        logger.debug("DID Document json - {}", doc.toJson());

        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(doc.getId())
                .build();

        Assertions.assertEquals(keyId, doc.getPublicKeyProperty(keyId).getId());
        Assertions.assertArrayEquals(algorithm.publicKeyToByte(keyProvider.getPublicKey()),
                algorithm.publicKeyToByte(doc.getPublicKeyProperty(keyId).getPublicKey()));

        logger.debug("file path : {}", new File(FILE_NAME).getPath());
        Keystore.storeDidKeyHolder(PASSWORD, didKeyHolder, FILE_NAME);
    }

    @Test
    @Order(4)
    void testUpdate() throws Exception {
        KeyWallet wallet = KeyWallet.load(new Bytes(TestKeys.ICON_WALLET_PRIVATE_KEY));
        DidKeyHolder keyHolder = Keystore.loadDidKeyHolder(PASSWORD, new File(FILE_NAME));
        logger.debug("file path : {}", new File(FILE_NAME).getPath());
        logger.debug("didKeyHolder : {}", keyHolder);

        String key2 = "newKey";
        AlgorithmProvider.Type type2 = AlgorithmProvider.Type.ES256K;
        Algorithm algorithm = AlgorithmProvider.create(type2);
        KeyProvider keyProvider2 = algorithm.generateKeyProvider(key2);

        Jwt addJwt = ScoreParameter.addKey(keyHolder, keyProvider2, EncodeType.BASE64);
        String signedJwt = keyHolder.sign(addJwt);
        Document doc = didService.addPublicKey(wallet, signedJwt);

        logger.debug("signedJwt - {}", signedJwt);
        logger.debug("DID Document - {}", doc);
        logger.debug("DID Document json - {}", doc.toJson());

        Assertions.assertEquals(key2, doc.getPublicKeyProperty(key2).getId());
        Assertions.assertArrayEquals(algorithm.publicKeyToByte(keyProvider2.getPublicKey()),
                algorithm.publicKeyToByte(doc.getPublicKeyProperty(key2).getPublicKey()));
    }

    @Test
    @Order(5)
    void testRevoke() throws Exception {
        KeyWallet wallet = KeyWallet.load(new Bytes(TestKeys.ICON_WALLET_PRIVATE_KEY));

        DidKeyHolder keyHolder = Keystore.loadDidKeyHolder(PASSWORD, new File(FILE_NAME));
        logger.debug("file path : {}", new File(FILE_NAME).getPath());
        logger.debug("didKeyHolder : {}", keyHolder);

        String revokeKeyId = "newKey";
        Jwt revokeJwt = ScoreParameter.revokeKey(keyHolder, revokeKeyId);
        String signedJwt = keyHolder.sign(revokeJwt);
        Document doc = didService.revokeKey(wallet, signedJwt);

        logger.debug("signedJwt - {}", signedJwt);
        logger.debug("DID Document - {}", doc);
        logger.debug("DID Document json - {}", doc.toJson());

        Assertions.assertTrue(doc.getPublicKeyProperty(revokeKeyId).isRevoked());
    }

    @Test
    @Order(3)
    void testReadDocument() throws Exception {
        DidKeyHolder keyHolder = Keystore.loadDidKeyHolder(PASSWORD, new File(FILE_NAME));

        Document doc = didService.readDocument(keyHolder.getDid());

        PublicKeyProperty didPublicKey = doc.getPublicKeyProperty(keyHolder.getKeyId());
        Assertions.assertNotNull(didPublicKey);
        Assertions.assertEquals(keyHolder.getKeyId(), didPublicKey.getId());

        logger.debug("DID Document json - {}", doc);
        logger.debug("DID Document json - {}", doc.toJson());
    }

    @Test
    void testCreateDocumentWalletPublicKey() throws KeyPairException, IOException, AlgorithmException {
        KeyWallet wallet = KeyWallet.load(new Bytes(TestKeys.ICON_WALLET_PRIVATE_KEY));
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
        Algorithm algorithm = AlgorithmProvider.create(type);
        String keyId = "IconWallet";

        PublicKey publicKey = algorithm.byteToPublicKey(wallet.getPublicKey().toByteArray());
        PrivateKey privateKey = algorithm.byteToPrivateKey(wallet.getPrivateKey().toByteArray());

        KeyProvider keyProvider = new KeyProvider.Builder()
                .keyId(keyId)
                .publicKey(publicKey)
                .privateKey(privateKey)
                .type(type)
                .build();

        String json = ScoreParameter.create(keyProvider, EncodeType.BASE64);
        logger.debug("DID Json - {}", json);
        Document doc = didService.create(wallet, json);
        logger.debug("DID Document - {}", doc);
        logger.debug("DID Document json - {}", doc.toJson());

        PublicKeyProperty didPublicKey = doc.getPublicKeyProperty(keyId);
        Assertions.assertEquals(keyId, didPublicKey.getId());
        Assertions.assertArrayEquals(algorithm.publicKeyToByte(keyProvider.getPublicKey()),
                algorithm.publicKeyToByte(doc.getPublicKeyProperty(keyId).getPublicKey()));
    }
}
