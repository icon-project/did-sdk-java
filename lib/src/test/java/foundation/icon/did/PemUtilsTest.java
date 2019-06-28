package foundation.icon.did;


import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.KeyProvider;
import foundation.icon.did.document.EncodeType;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PemUtilsTest {

    private final static Logger logger = LoggerFactory.getLogger(PemUtilsTest.class);

    @Test
    void testWriteRS256PemFile() throws Exception {
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.RS256);
        PublicKey key = algorithm.byteToPublicKey(EncodeType.HEX.decode(TestKeys.PUBLIC_KEY_RS256));

        PemObject pemObject = new PemObject("PUBLIC KEY", key.getEncoded());
        File file = new File("test-public.pem");
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(fileOutputStream));
        pemWriter.writeObject(pemObject);
        pemWriter.close();

        byte[] b = parsePEMFile(file);
        PublicKey p = getPublicKey(b, "RSA");
        Assertions.assertArrayEquals(key.getEncoded(), p.getEncoded());
    }

    @Test
    void testWriteES256PemFile() throws Exception {
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256);
        PublicKey key = algorithm.byteToPublicKey(EncodeType.HEX.decode(TestKeys.PUBLIC_KEY_ES256));

        PemObject pemObject = new PemObject("PUBLIC KEY", key.getEncoded());
        File file = new File("test-es-public.pem");
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(fileOutputStream));
        pemWriter.writeObject(pemObject);
        pemWriter.close();

        byte[] b = parsePEMFile(file);
        PublicKey p = getPublicKey(b, "EC");
        Assertions.assertArrayEquals(key.getEncoded(), p.getEncoded());
    }

    @Test
    void testWriteNewES256PemFile() throws Exception {
        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;
        Algorithm algorithm = AlgorithmProvider.create(type);
        KeyPair keyPair = algorithm.generateKeyPair();
        KeyProvider keyProvider = new KeyProvider.Builder()
                .keyId("new")
                .publicKey(keyPair.getPublic())
                .type(type)
                .build();
        PublicKey key = keyProvider.getPublicKey();
        PemObject pemObject = new PemObject("PUBLIC KEY", key.getEncoded());
        File file = new File("test-es-public.pem");
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(fileOutputStream));
        pemWriter.writeObject(pemObject);
        pemWriter.close();

        byte[] b = parsePEMFile(file);
        PublicKey p = getPublicKey(b, "EC");
        Assertions.assertArrayEquals(key.getEncoded(), p.getEncoded());
    }

    private static byte[] parsePEMFile(File pemFile) throws IOException {
        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        PemReader reader = new PemReader(new FileReader(pemFile));
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return content;
    }

    private static PublicKey getPublicKey(byte[] keyBytes, String algorithm) {
        PublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        }

        return publicKey;
    }

    private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) {
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the private key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the private key");
        }

        return privateKey;
    }
}
