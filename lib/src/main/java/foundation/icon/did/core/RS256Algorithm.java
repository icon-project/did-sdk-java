package foundation.icon.did.core;

import foundation.icon.did.exceptions.AlgorithmException;

import java.security.*;

import static foundation.icon.did.core.AlgorithmProvider.PROVIDER;
import static foundation.icon.did.core.AlgorithmProvider.secureRandom;

public class RS256Algorithm implements Algorithm {

    private AlgorithmProvider.Type type = AlgorithmProvider.Type.RS256;

    RS256Algorithm() {
    }

    @Override
    public AlgorithmProvider.Type getType() {
        return type;
    }

    @Override
    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", PROVIDER);
        gen.initialize(2048, secureRandom());
        return gen.generateKeyPair();
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws AlgorithmException {
        return signWithSignature(type.getSigAlgorithm(), privateKey, data);
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws AlgorithmException {
        return verifyWithSignature(type.getSigAlgorithm(), publicKey, data, signature);
    }

}
