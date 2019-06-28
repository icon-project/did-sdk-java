package foundation.icon.did.core;

import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.exceptions.KeyPairException;

import java.security.*;

public class NoneAlgorithm implements Algorithm {

    private AlgorithmProvider.Type type = AlgorithmProvider.Type.NONE;

    @Override
    public AlgorithmProvider.Type getType() {
        return type;
    }

    @Override
    public KeyProvider generateKeyProvider(String keyId) throws AlgorithmException {
        return null;
    }

    @Override
    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return null;
    }

    @Override
    public byte[] signWithSignature(String algorithm, PrivateKey privateKey, byte[] data) throws AlgorithmException {
        return new byte[0];
    }

    @Override
    public boolean verifyWithSignature(String algorithm, PublicKey publicKey, byte[] data, byte[] signature) throws AlgorithmException {
        return true;
    }

    @Override
    public byte[] publicKeyToByte(PublicKey publicKey) {
        return new byte[0];
    }

    @Override
    public byte[] privateKeyToByte(PrivateKey privateKey) {
        return new byte[0];
    }

    @Override
    public PublicKey byteToPublicKey(byte[] b) throws KeyPairException {
        return null;
    }

    @Override
    public PrivateKey byteToPrivateKey(byte[] b) throws KeyPairException {
        return null;
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws AlgorithmException {
        return new byte[0];
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws AlgorithmException {
        return true;
    }
}
