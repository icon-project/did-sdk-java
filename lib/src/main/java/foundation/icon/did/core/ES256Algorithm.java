package foundation.icon.did.core;

import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.exceptions.JwtException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.util.BigIntegers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static foundation.icon.did.core.AlgorithmProvider.PROVIDER;
import static foundation.icon.did.core.AlgorithmProvider.secureRandom;
import static foundation.icon.did.core.PropertyName.EC_CURVE_PARAM_SECP256R1;

public class ES256Algorithm implements Algorithm {

    public static final int EC_256_NUMBER = 32;
    private AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;

    ES256Algorithm() {
    }

    @Override
    public AlgorithmProvider.Type getType() {
        return type;
    }

    @Override
    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator pairGen = KeyPairGenerator.getInstance("EC", PROVIDER);
        pairGen.initialize(new ECGenParameterSpec(EC_CURVE_PARAM_SECP256R1), secureRandom());
        return pairGen.generateKeyPair();
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws AlgorithmException {
        byte[] signature = signWithSignature(type.getSigAlgorithm(), privateKey, data);
        return ecDerDecode(signature, EC_256_NUMBER);
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws AlgorithmException {
        try {
            signature = ecDerEncode(signature, EC_256_NUMBER);
        } catch (IOException e) {
            throw new JwtException(e.getMessage(), e.getCause());
        }
        return verifyWithSignature(type.getSigAlgorithm(), publicKey, data, signature);
    }

    static byte[] ecDerDecode(byte[] signature, int ecNumberSize) {
        try (ASN1InputStream decoder = new ASN1InputStream(signature)) {
            DLSequence seq = (DLSequence) decoder.readObject();
            ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
            ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);

            ByteBuffer buffer = ByteBuffer.allocate(ecNumberSize * 2);
            buffer.put(BigIntegers.asUnsignedByteArray(ecNumberSize, r.getValue()));
            buffer.put(BigIntegers.asUnsignedByteArray(ecNumberSize, s.getValue()));
            return buffer.array();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] ecDerEncode(byte[] signature, int ecNumberSize) throws IOException {
        byte[] r = new byte[ecNumberSize];
        byte[] s = new byte[ecNumberSize];
        System.arraycopy(signature, 0, r, 0, ecNumberSize);
        System.arraycopy(signature, ecNumberSize, s, 0, ecNumberSize);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DERSequenceGenerator seq = new DERSequenceGenerator(baos);
        seq.addObject(new ASN1Integer(new BigInteger(1, r)));
        seq.addObject(new ASN1Integer(new BigInteger(1, s)));
        seq.close();
        return baos.toByteArray();
    }

}
