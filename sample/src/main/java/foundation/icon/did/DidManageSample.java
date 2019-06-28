package foundation.icon.did;

import foundation.icon.did.config.SampleConfig;
import foundation.icon.did.config.SampleKeys;
import foundation.icon.did.core.*;
import foundation.icon.did.document.Document;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.exception.SampleException;
import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.exceptions.KeyPairException;
import foundation.icon.did.exceptions.KeystoreException;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.score.ScoreParameter;
import foundation.icon.icx.IconService;
import foundation.icon.icx.KeyWallet;
import foundation.icon.icx.data.Address;
import foundation.icon.icx.data.Bytes;
import foundation.icon.icx.data.IconAmount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;

@SuppressWarnings("Duplicates")
public class DidManageSample {

    public static Logger logger = LoggerFactory.getLogger(DidManageSample.class);

    public static void printDocument(Document document) {
        logger.debug("DID Document : {}", document);
        logger.debug("DID Document json: {}\n", document.toJson());
    }

    public static void main(String[] args) throws IOException, KeystoreException, KeyPairException {

        // Create objects for connecting ICON Network
        SampleConfig config = SampleConfig.local();
        BigInteger networkId = config.getNetworkId();
        IconService iconService = config.iconService();

        // DID Document Score Address
        Address scoreAddress = config.getScoreAddress();

        // Create the DidService object
        DidService didService = new DidService(iconService, networkId, scoreAddress);

        KeyWallet wallet = KeyWallet.load(new Bytes(SampleKeys.ISSUER_WALLET_PRIVATE_KEY));
        BigInteger balance = iconService.getBalance(wallet.getAddress()).execute();
        if (balance.compareTo(IconAmount.of("1", IconAmount.Unit.ICX).toLoop()) < 0) {
            throw new SampleException("the balance of " + wallet.getAddress() + " < 1 icx\n Use your KeyWallet");
        }

        logger.debug(" ### CREATE DID Document");
        // the id for publicKey/privateKey
        String keyId = "sampleKey1";

        // Generate a new KeyProvider object
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
        KeyProvider keyProvider = null;
        try {
            keyProvider = algorithm.generateKeyProvider(keyId);
        } catch (Exception e) {
            throw new SampleException("KeyProvider creation failed");
        }
        logger.debug("key provider : {}", keyProvider);

        EncodeType encodeType = EncodeType.BASE64;

        // Send a transaction to create a DID document
        Document document = null;
        try {
            String json = ScoreParameter.create(keyProvider, encodeType);
            document = didService.create(wallet, json);
        } catch (IOException e) {
            throw new SampleException("DID document creation failed \n" + e.getMessage());
        }

        // print DID Document
        printDocument(document);

        logger.debug(" ### Store the key information for using did.");
        String password = "P@ssw0rd";
        File file = new File("./");
        DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(document.getId())
                .build();
        Keystore.storeDidKeyHolder(password, didKeyHolder, file);
        DidKeyHolder k = Keystore.loadDidKeyHolder(password, new File(document.getId() + ".json"));
        logger.debug("load KeyProvider : {}\n", k);

        logger.debug(" ### READ Document");
        // Get a id of DID Document
        String did = document.getId();
        logger.debug("DID : {}", did);

        try {
            document = didService.readDocument(did);
        } catch (IOException e) {
            throw new SampleException(e.getMessage());
        }

        // print DID Document
        printDocument(document);


        logger.debug(" ### Add public key");
        // the id of publicKey/privateKey to add
        String newKeyId = "sampleKey2";

        // Generate a new KeyProvider object
        KeyProvider newKeyProvider = null;
        algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
        try {
            newKeyProvider = algorithm.generateKeyProvider(newKeyId);
        } catch (Exception e) {
            throw new SampleException("KeyProvider creation failed");
        }
        logger.debug("add key porvider : {}", keyProvider);

        encodeType = EncodeType.BASE64;

        // Send a transaction to add a publicKey to the DID document
        try {
            Jwt addJwt = ScoreParameter.addKey(didKeyHolder, newKeyProvider, encodeType);
            document = didService.addPublicKey(wallet, didKeyHolder.sign(addJwt));
        } catch (IOException e) {
            throw new SampleException("Failed to add public key \n" + e.getMessage());
        } catch (AlgorithmException e) {
            throw new SampleException("Failed to sign \n" + e.getMessage());
        }

        // print DID Document
        printDocument(document);

        logger.debug(" ### Revoke public key");
        logger.debug("revoke key id : {}", newKeyId);
        try {
            Jwt revokeJwt = ScoreParameter.revokeKey(didKeyHolder, newKeyId);
            document = didService.revokeKey(wallet, didKeyHolder.sign(revokeJwt));
        } catch (IOException e) {
            throw new SampleException("Failed to revoke public key \n" + e.getMessage());
        } catch (AlgorithmException e) {
            throw new SampleException("Failed to sign \n" + e.getMessage());
        }

        // print DID Document
        printDocument(document);

        logger.debug(" ### The end");

    }

}
