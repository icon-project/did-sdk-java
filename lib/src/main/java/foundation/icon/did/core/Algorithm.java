package foundation.icon.did.core;

import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.exceptions.KeyPairException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * This interface use in the Signing or Verification process of a icon-DID.
 */
public interface Algorithm {

    /**
     * Get the type of Algorithm
     *
     * @return the Type object
     */
    AlgorithmProvider.Type getType();

    /**
     * Sign the given data using this Algorithm instance and the privateKey.
     *
     * @param privateKey the privateKey object
     * @param data       an array of bytes representing the base64 encoded content to be verified against the signature.
     * @return the signature bytes
     */
    byte[] sign(PrivateKey privateKey, byte[] data) throws AlgorithmException;

    /**
     * Verify the given token using this Algorithm instance.
     *
     * @param publicKey the publicKey object to use in the verify
     * @param data      the array of bytes used for signing
     * @param signature the signature bytes
     * @return if the signature is valid, return true, or return false
     */
    boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws AlgorithmException;

    /**
     * Create a KeyProvider object.
     * <p>
     * This will generate a new public/private key every time it is called.
     * and return the id of key, the type of this algorithm instance and the new public/private key.
     *
     * @param keyId the id of the key to use in the DID document
     * @return the KeyProvider object
     */
    default KeyProvider generateKeyProvider(String keyId) throws AlgorithmException {
        try {
            KeyPair keyPair = generateKeyPair();
            return new KeyProvider.Builder()
                    .keyId(keyId)
                    .publicKey(keyPair.getPublic())
                    .privateKey(keyPair.getPrivate())
                    .type(getType())
                    .build();
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new AlgorithmException(e);
        }
    }

    KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException;

    /**
     * Sign the given data using the Signature instance and the privateKey.
     * {@linkplain java.security.Signature}
     *
     * @param algorithm  the name of algorithm
     * @param privateKey the privateKey object to use in the signing
     * @param data       an array of bytes representing the base64 encoded content to be verified against the signature.
     * @return the signature bytes
     */
    default byte[] signWithSignature(String algorithm, PrivateKey privateKey, byte[] data) throws AlgorithmException {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new AlgorithmException(e);
        }

    }

    /**
     * Verify the given token using the Signature instance.
     * {@linkplain java.security.Signature}
     *
     * @param algorithm the name of algorithm
     * @param publicKey the publicKey object to use in the verify
     * @param data      the array of bytes used for signing
     * @param signature the signature bytes
     * @return if the signature is valid, return true, or return false
     */
    default boolean verifyWithSignature(String algorithm, PublicKey publicKey, byte[] data, byte[] signature) throws AlgorithmException {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new AlgorithmException(e);
        }

    }

    /**
     * Returns the byte array in primary encoding format of the publicKey object.
     * {@linkplain #byteToPublicKey(byte[])}
     *
     * @param publicKey the publicKey object returned from {@linkplain #generateKeyProvider(String)}
     * @return the byte array in primary encoding format of the publicKey object
     */
    default byte[] publicKeyToByte(PublicKey publicKey) {
        return publicKey.getEncoded();
    }

    /**
     * Returns the byte array in primary encoding format of the privateKey object.
     * {@linkplain #byteToPrivateKey(byte[])}
     *
     * @param privateKey the privateKey object returned from {@linkplain #generateKeyProvider(String)}
     * @return the byte array in primary encoding format of the privateKey object
     */
    default byte[] privateKeyToByte(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    /**
     * Convert the byte array to the PublicKey object.
     *
     * @param b the byte array returned from {@linkplain #publicKeyToByte(PublicKey)}
     * @return the PublicKey object
     */
    default PublicKey byteToPublicKey(byte[] b) throws KeyPairException {
        try {
            KeyFactory kf = KeyFactory.getInstance(getType().getKeyAlgorithm());
            return kf.generatePublic(new X509EncodedKeySpec(b));
        } catch (NoSuchAlgorithmException e) {
            throw new KeyPairException("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            throw new KeyPairException("Could not reconstruct the public key");
        }
    }

    /**
     * Convert the byte array to the PrivateKey object.
     *
     * @param b the byte array returned from {@linkplain #privateKeyToByte(PrivateKey)}
     * @return the PrivateKey object
     */
    default PrivateKey byteToPrivateKey(byte[] b) throws KeyPairException {
        try {
            KeyFactory kf = KeyFactory.getInstance(getType().getKeyAlgorithm());
            return kf.generatePrivate(new PKCS8EncodedKeySpec(b));
        } catch (NoSuchAlgorithmException e) {
            throw new KeyPairException("Could not reconstruct the private key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            throw new KeyPairException("Could not reconstruct the private key");
        }
    }

}
