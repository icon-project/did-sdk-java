package foundation.icon.did.core;


import com.google.gson.Gson;
import foundation.icon.did.exceptions.KeyPairException;
import foundation.icon.did.exceptions.KeystoreException;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.UUID;


/**
 * Original Code
 * https://github.com/web3j/web3j/blob/master/crypto/src/main/java/org/web3j/crypto/Wallet.java
 *
 * <p>Ethereum wallet file management. For reference, refer to
 * <a href="https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition">
 * Web3 Secret Storage Definition</a> or the
 * <a href="https://github.com/ethereum/go-ethereum/blob/master/accounts/key_store_passphrase.go">
 * Go Ethereum client implementation</a>.</p>
 *
 * <p><strong>Note:</strong> the Bouncy Castle Scrypt implementation
 * {@link SCrypt}, fails to comply with the following
 * Ethereum reference
 * <a href="https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition#scrypt">
 * Scrypt test vector</a>:</p>
 *
 * <pre>
 * {@code
 * // Only value of r that cost (as an int) could be exceeded for is 1
 * if (r == 1 && N_STANDARD > 65536)
 * {
 *     throw new IllegalArgumentException("Cost parameter N_STANDARD must be > 1 and < 65536.");
 * }
 * }
 * </pre>
 */
public class Keystore {

    private Keystore() {
    }

    private static final int N_STANDARD = 1 << 14;
    private static final int P_STANDARD = 1;

    private static final int R = 8;
    private static final int DKLEN = 32;

    private static final int CURRENT_VERSION = 3;

    private static final String CIPHER = "aes-128-ctr";
    static final String SCRYPT = "scrypt";

    /**
     * Store the DidKeyHolder object as a file.
     * <p>
     * It stores the id of DID Document, the id of publicKey and private key cryptographically.
     * The reason we do not store the public key is because we can get it from the blockchain using
     * the id of DID Document and the id of publicKey.
     *
     * @param password             the string to use for encryption
     * @param didKeyHolder          the didKeyHolder object
     * @param destinationDirectory the File object
     * @return a name of created file
     */
    public static String storeDidKeyHolder(String password, DidKeyHolder didKeyHolder, File destinationDirectory) throws KeystoreException, IOException {
        KeystoreFile keystoreFile = create(password, didKeyHolder, N_STANDARD, P_STANDARD);
        return generateFile(keystoreFile, destinationDirectory);
    }

    /**
     * Store the DidKeyHolder object as a file.
     * <p>
     * It stores the id of DID Document, the id of publicKey and private key cryptographically.
     * The reason we do not store the public key is because we can get it from the blockchain using
     * the id of DID Document and the id of publicKey.
     *
     * @param password    the string to use for encryption
     * @param didKeyHolder          the didKeyHolder object
     * @param fileName    the name of file to be created
     */
    public static void storeDidKeyHolder(String password, DidKeyHolder didKeyHolder, String fileName) throws KeystoreException, IOException {
        KeystoreFile keystoreFile = create(password, didKeyHolder, N_STANDARD, P_STANDARD);
        try (Writer writer = new FileWriter(fileName)) {
            new Gson().toJson(keystoreFile, writer);
        }
    }

    /**
     * Returns a DidKeyHolder stored as a file. {@linkplain #storeDidKeyHolder(String, DidKeyHolder, File)}
     *
     * @param password the string used for encryption
     * @param source   the file object
     * @return the DidKeyHolder object
     */
    public static DidKeyHolder loadDidKeyHolder(String password, File source)
            throws IOException, KeystoreException, KeyPairException {

        InputStreamReader reader = new InputStreamReader(new FileInputStream(source));
        KeystoreFile keystoreFile = new Gson().fromJson(reader, KeystoreFile.class);
        return decrypt(password, keystoreFile);
    }

    // did, kid, type
    private static KeystoreFile create(String password, DidKeyHolder didKeyHolder, int n, int p)
            throws KeystoreException {
        if (didKeyHolder.getPrivateKey() == null) {
            throw new IllegalArgumentException("Private Key cannot be null.");
        }

        byte[] salt = generateRandomBytes(32);

        byte[] derivedKey = generateDerivedScryptKey(
                password.getBytes(StandardCharsets.UTF_8), salt, n, R, p, DKLEN);

        byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
        byte[] iv = generateRandomBytes(16);

        Algorithm algorithm = AlgorithmProvider.create(didKeyHolder.getType());
        byte[] privateKeyBytes = algorithm.privateKeyToByte(didKeyHolder.getPrivateKey());


        byte[] cipherText = performCipherOperation(
                Cipher.ENCRYPT_MODE, iv, encryptKey, privateKeyBytes);

        byte[] mac = generateMac(derivedKey, cipherText);

        return createKeystoreFile(didKeyHolder, cipherText, iv, salt, mac, n, p);
    }


    private static KeystoreFile createKeystoreFile(
            DidKeyHolder keyHolder, byte[] cipherText, byte[] iv, byte[] salt, byte[] mac,
            int n, int p) {

        KeystoreFile keystoreFile = new KeystoreFile();
        keystoreFile.setDid(keyHolder.getDid());
        keystoreFile.setKeyId(keyHolder.getKeyId());
        keystoreFile.setType(keyHolder.getType().getName());

        KeystoreFile.Crypto crypto = new KeystoreFile.Crypto();
        crypto.setCipher(CIPHER);
        crypto.setCiphertext(Hex.toHexString(cipherText));
        keystoreFile.setCrypto(crypto);

        KeystoreFile.CipherParams cipherParams = new KeystoreFile.CipherParams();
        cipherParams.setIv(Hex.toHexString(iv));
        crypto.setCipherparams(cipherParams);

        crypto.setKdf(SCRYPT);
        KeystoreFile.ScryptKdfParams kdfParams = new KeystoreFile.ScryptKdfParams();
        kdfParams.setDklen(DKLEN);
        kdfParams.setN(n);
        kdfParams.setP(p);
        kdfParams.setR(R);
        kdfParams.setSalt(Hex.toHexString(salt));
        crypto.setKdfparams(kdfParams);

        crypto.setMac(Hex.toHexString(mac));
        keystoreFile.setCrypto(crypto);
        keystoreFile.setId(UUID.randomUUID().toString());
        keystoreFile.setVersion(CURRENT_VERSION);
        return keystoreFile;
    }

    private static byte[] generateDerivedScryptKey(
            byte[] password, byte[] salt, int n, int r, int p, int dkLen) {
        return SCrypt.generate(password, salt, n, r, p, dkLen);
    }

    private static byte[] performCipherOperation(
            int mode, byte[] iv, byte[] encryptKey, byte[] text) throws KeystoreException {

        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            SecretKeySpec secretKeySpec = new SecretKeySpec(encryptKey, "AES");
            cipher.init(mode, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(text);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | InvalidKeyException
                | BadPaddingException | IllegalBlockSizeException e) {
            throw new KeystoreException("Error performing cipher operation", e);
        }
    }

    private static byte[] generateMac(byte[] derivedKey, byte[] cipherText) {
        byte[] result = new byte[16 + cipherText.length];

        System.arraycopy(derivedKey, 16, result, 0, 16);
        System.arraycopy(cipherText, 0, result, 16, cipherText.length);

        Keccak.DigestKeccak kecc = new Keccak.Digest256();
        kecc.update(result, 0, result.length);
        return kecc.digest();
    }

    private static DidKeyHolder decrypt(String password, KeystoreFile keystoreFile)
            throws KeystoreException, KeyPairException {

        validate(keystoreFile);

        KeystoreFile.Crypto crypto = keystoreFile.getCrypto();

        byte[] mac = Hex.decode(crypto.getMac());
        byte[] iv = Hex.decode(crypto.getCipherparams().getIv());
        byte[] cipherText = Hex.decode(crypto.getCiphertext());

        KeystoreFile.ScryptKdfParams scryptKdfParams = crypto.getKdfparams();
        int dklen = scryptKdfParams.getDklen();
        int n = scryptKdfParams.getN();
        int p = scryptKdfParams.getP();
        int r = scryptKdfParams.getR();
        byte[] salt = Hex.decode(scryptKdfParams.getSalt());
        byte[] derivedKey = generateDerivedScryptKey(password.getBytes(StandardCharsets.UTF_8), salt, n, r, p, dklen);
        byte[] derivedMac = generateMac(derivedKey, cipherText);

        if (!Arrays.equals(derivedMac, mac)) {
            throw new KeystoreException("Invalid password provided");
        }

        byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
        byte[] privateKey = performCipherOperation(Cipher.DECRYPT_MODE, iv, encryptKey, cipherText);

        AlgorithmProvider.Type type = AlgorithmProvider.Type.fromName(keystoreFile.getType());
        Algorithm algorithm = AlgorithmProvider.create(type);
        PrivateKey pk = algorithm.byteToPrivateKey(privateKey);
        return new DidKeyHolder.Builder()
                .did(keystoreFile.getDid())
                .keyId(keystoreFile.getKeyId())
                .type(AlgorithmProvider.Type.fromName(keystoreFile.getType()))
                .privateKey(pk)
                .build();
    }

    private static void validate(KeystoreFile keystoreFile) throws KeystoreException {
        KeystoreFile.Crypto crypto = keystoreFile.getCrypto();

        if (keystoreFile.getVersion() != CURRENT_VERSION) {
            throw new KeystoreException("Keystore version is not supported");
        }

        if (!crypto.getCipher().equals(CIPHER)) {
            throw new KeystoreException("Keystore cipher is not supported");
        }

        if (!crypto.getKdf().equals(SCRYPT)) {
            throw new KeystoreException("KDF type is not supported");
        }

    }

    private static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        AlgorithmProvider.secureRandom().nextBytes(bytes);
        return bytes;
    }

    private static String generateFile(KeystoreFile file, File destinationDirectory) throws IOException {
        String fileName = file.getDid() + ".json";
        File destination = new File(destinationDirectory, fileName);
        try (Writer writer = new FileWriter(destination)) {
            new Gson().toJson(file, writer);
        }
        return fileName;
    }

}
