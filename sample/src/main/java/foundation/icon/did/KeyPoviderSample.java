package foundation.icon.did;


import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.KeyProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class KeyPoviderSample {

    private static Logger logger = LoggerFactory.getLogger(KeyPoviderSample.class);


    /**
     * Create a new KeyProvider using Secp256k algorithm.
     */
    private KeyProvider generateES256K() throws Exception {
        String keyId = "new-ES256Key";
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
        return algorithm.generateKeyProvider(keyId);
    }

    public static void main(String[] args) throws Exception {

        KeyPoviderSample sample = new KeyPoviderSample();

        // Create a new KeyProvider
        KeyProvider keyProvider = sample.generateES256K();
        logger.debug("new ES256K KeyProvider : {}", keyProvider);

        // Create the algorithm object
        Algorithm algorithm = AlgorithmProvider.create(keyProvider.getType());
        // Important information that user need to have
        String keyId = keyProvider.getKeyId();
        String type = keyProvider.getType().getName();
        String privateKey = Hex.toHexString(algorithm.privateKeyToByte(keyProvider.getPrivateKey()));
        String publicKey = Hex.toHexString(algorithm.publicKeyToByte(keyProvider.getPublicKey()));

        // Create a KeyProvider from each String
        algorithm = AlgorithmProvider.create(keyProvider.getType());
        KeyProvider loadKeyProvider = new KeyProvider.Builder()
                .keyId(keyId)
                .publicKey(algorithm.byteToPublicKey(Hex.decode(publicKey)))
                .privateKey(algorithm.byteToPrivateKey(Hex.decode(privateKey)))
                .type(AlgorithmProvider.Type.fromName(type))
                .build();

        logger.debug("loadDidKeyHolder == didKeyHolder : {}", keyProvider.equals(loadKeyProvider));
    }
}
