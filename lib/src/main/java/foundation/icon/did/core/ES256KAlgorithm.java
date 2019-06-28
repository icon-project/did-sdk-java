package foundation.icon.did.core;

import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.exceptions.KeyPairException;
import foundation.icon.icx.crypto.ECDSASignature;
import foundation.icon.icx.crypto.IconKeys;
import foundation.icon.icx.data.Bytes;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static foundation.icon.did.core.AlgorithmProvider.PROVIDER;
import static foundation.icon.did.core.AlgorithmProvider.secureRandom;
import static foundation.icon.did.core.PropertyName.EC_CURVE_PARAM_SECP256K1;

public class ES256KAlgorithm implements Algorithm {

    private AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;

    private ECNamedCurveParameterSpec spec;
    private ECParameterSpec ecparameterSpec;

    ES256KAlgorithm() {
        spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ecparameterSpec = new ECParameterSpec(spec.getCurve(), spec.getG(), spec.getN());
    }

    @Override
    public AlgorithmProvider.Type getType() {
        return type;
    }

    @Override
    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator pairGen = KeyPairGenerator.getInstance("EC", PROVIDER);
        pairGen.initialize(new ECGenParameterSpec(EC_CURVE_PARAM_SECP256K1), secureRandom());
        return pairGen.generateKeyPair();
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws AlgorithmException {
        Bytes p = new Bytes(privateKeyToByte(privateKey));
        ECDSASignature signature = new ECDSASignature(p);
        byte[] hash = new SHA3.Digest256().digest(data);
        BigInteger[] sig = signature.generateSignature(hash);
        return signature.recoverableSerialize(sig, hash);
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws AlgorithmException {
        try {
            byte[] pub = ((ECPublicKey) publicKey).getQ().getEncoded(false);
            byte[] sigr = Arrays.copyOfRange(signature, 0, ES256Algorithm.EC_256_NUMBER);
            byte[] sigs = Arrays.copyOfRange(signature, ES256Algorithm.EC_256_NUMBER, ES256Algorithm.EC_256_NUMBER * 2);

            ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
            ECPublicKeyParameters publicKeyParams =
                    new ECPublicKeyParameters(spec.getCurve().decodePoint(pub), domain);

            ECDSASigner signer = new ECDSASigner();
            signer.init(false, publicKeyParams);
            byte[] hash = new SHA3.Digest256().digest(data);
            return signer.verifySignature(hash, new BigInteger(1, sigr), new BigInteger(1, sigs));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public byte[] publicKeyToByte(PublicKey publicKey) {
        return ((ECPublicKey) publicKey).getQ().getEncoded(false);
    }

    @Override
    public byte[] privateKeyToByte(PrivateKey privateKey) {
        return BigIntegers.asUnsignedByteArray(IconKeys.PRIVATE_KEY_SIZE, ((BCECPrivateKey) privateKey).getD());
    }

    @Override
    public PublicKey byteToPublicKey(byte[] b) throws KeyPairException {
        try {
            KeyFactory fact = KeyFactory.getInstance(type.getKeyAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            return fact.generatePublic(new ECPublicKeySpec(spec.getCurve().decodePoint(b), ecparameterSpec));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new KeyPairException("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            throw new KeyPairException("Could not reconstruct the public key");
        }
    }

    @Override
    public PrivateKey byteToPrivateKey(byte[] b) throws KeyPairException {
        try {
            KeyFactory fact = KeyFactory.getInstance(type.getKeyAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            return fact.generatePrivate(new ECPrivateKeySpec(new BigInteger(1, b), ecparameterSpec));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new KeyPairException("Could not reconstruct the private key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            throw new KeyPairException("Could not reconstruct the private key");
        }
    }
}
