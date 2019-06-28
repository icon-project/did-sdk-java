package foundation.icon.did;

import foundation.icon.did.config.SampleConfig;
import foundation.icon.did.config.SampleKeys;
import foundation.icon.did.core.*;
import foundation.icon.did.document.Document;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.document.PublicKeyProperty;
import foundation.icon.did.exception.SampleException;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.protocol.ClaimRequest;
import foundation.icon.did.score.ScoreParameter;
import foundation.icon.did.util.FileUtils;
import foundation.icon.icx.IconService;
import foundation.icon.icx.KeyWallet;
import foundation.icon.icx.data.Address;
import foundation.icon.icx.data.Bytes;
import foundation.icon.icx.data.IconAmount;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.*;

@SuppressWarnings("Duplicates")
public class CredentialSample {

    private static Logger logger = LoggerFactory.getLogger(CredentialSample.class);

    public static void main(String[] args) throws Exception {

        // Create objects for connecting ICON Network
        SampleConfig config = SampleConfig.local();
        BigInteger networkId = config.getNetworkId();
        IconService iconService = config.iconService();

        // DID Document Score Address
        Address scoreAddress = config.getScoreAddress();

        // Create the DidService object
        DidService didService = new DidService(iconService, networkId, scoreAddress);

        logger.debug(" ### Check DID of owner and issuer");
        KeyWallet ownerWallet = KeyWallet.load(new Bytes(SampleKeys.OWNER_WALLET_PRIVATE_KEY));
        DidKeyHolder ownerKeyHolder = null;
        try {
            ownerKeyHolder = Keystore.loadDidKeyHolder(SampleConfig.TEST_PASSWORD, new File(SampleConfig.OWNER_KEY_FILE_NAME));
        } catch (IOException e) {
            BigInteger balance = iconService.getBalance(ownerWallet.getAddress()).execute();
            if (balance.compareTo(IconAmount.of("1", IconAmount.Unit.ICX).toLoop()) < 0) {
                throw new SampleException("the balance of " + ownerWallet.getAddress() + " < 1 icx\n Use your KeyWallet");
            }

            Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
            KeyProvider keyProvider = algorithm.generateKeyProvider(SampleKeys.OWNER_KEY_ID);
            String json = ScoreParameter.create(keyProvider, EncodeType.BASE64);
            Document document = didService.create(ownerWallet, json);
            logger.debug("create owner did : {}", document.getId());

            ownerKeyHolder = new DidKeyHolder.Builder(keyProvider)
                    .did(document.getId())
                    .build();
            Keystore.storeDidKeyHolder(SampleConfig.TEST_PASSWORD, ownerKeyHolder, SampleConfig.OWNER_KEY_FILE_NAME);
        }

        logger.debug("owner key provider : {}", ownerKeyHolder);
        Document ownerDocument = didService.readDocument(ownerKeyHolder.getDid());
        logger.debug("owner document : {}", ownerDocument.toJson());


        KeyWallet issuerWallet = KeyWallet.load(new Bytes(SampleKeys.ISSUER_WALLET_PRIVATE_KEY));
        DidKeyHolder issuerKeyHolder = null;
        try {
            issuerKeyHolder = Keystore.loadDidKeyHolder(SampleConfig.TEST_PASSWORD, new File(SampleConfig.ISSUER_KEY_FILE_NAME));
        } catch (IOException e) {
            BigInteger balance = iconService.getBalance(issuerWallet.getAddress()).execute();
            if (balance.compareTo(IconAmount.of("1", IconAmount.Unit.ICX).toLoop()) < 0) {
                throw new SampleException("the balance of " + issuerWallet.getAddress() + " < 1 icx\n Use your KeyWallet");
            }

            Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
            KeyProvider keyProvider = algorithm.generateKeyProvider(SampleKeys.ISSUER_KEY_ID);

            String json = ScoreParameter.create(keyProvider, EncodeType.BASE64);
            Document document = didService.create(issuerWallet, json);
            logger.debug("create issuer did : {}", document.getId());

            issuerKeyHolder = new DidKeyHolder.Builder(keyProvider)
                    .did(document.getId())
                    .build();
            Keystore.storeDidKeyHolder(SampleConfig.TEST_PASSWORD, issuerKeyHolder, SampleConfig.ISSUER_KEY_FILE_NAME);
        }

        logger.debug("issuer key provider : {}", issuerKeyHolder);
        Document issuerDocument = didService.readDocument(issuerKeyHolder.getDid());
        logger.debug("issuer document : {}\n", issuerDocument.toJson());

        logger.debug(" ### Request Credential to issuer");
        List<String> requestClaimTypes = Arrays.asList("email");
        List<String> requestClaimValues = Arrays.asList("abc@icon.foundation");
        Map claims = new HashMap();
        for (int i = 0; i < requestClaimTypes.size(); i++) {
            claims.put(requestClaimTypes.get(i), requestClaimValues.get(i));
        }

        String nonce = Hex.toHexString(AlgorithmProvider.secureRandom().generateSeed(4));

        // Create the ClaimRequest object
        ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.CREDENTIAL)
                .didKeyHolder(ownerKeyHolder)
                .requestClaims(claims)
                .responseId(issuerKeyHolder.getDid())
                .nonce(nonce)
                .build();

        // Signs is with the given algorithm and Encodes to base64
        String requestJwt = ownerKeyHolder.sign(request.getJwt());
        logger.debug("request credential : {}\n", requestJwt);

        logger.debug(" ### Issuer verify request of owner");

        // Decode a given Json Web Token
        ClaimRequest claimRequest = ClaimRequest.valueOf(requestJwt);
        logger.debug("REQ_CREDENTIAL Info");
        logger.debug("  type : {}", claimRequest.getTypes());
        logger.debug("  claims : {}", claimRequest.getClaims());
        logger.debug("  requestId : {}", claimRequest.getRequestId());
        logger.debug("  responseId : {}", claimRequest.getResponseId());
        logger.debug("  request date : {}", claimRequest.getRequestDate());
        logger.debug("  nonce : {}\n", claimRequest.getNonce());

        logger.debug("check responseId : {}\n", issuerKeyHolder.getDid().equals(claimRequest.getResponseId()));

        String ownerDid = claimRequest.getRequestId();
        logger.debug("check did of request : {}", ownerDid);

        // Read a DID document
        ownerDocument = didService.readDocument(ownerDid);
        logger.debug("check document of owner : {}", ownerDocument.toJson());

        // Verify that the publicKey is revoked
        PublicKeyProperty publicKeyProperty = ownerDocument.getPublicKeyProperty(claimRequest.getKeyId());
        boolean isRevoked = publicKeyProperty.isRevoked();
        logger.debug("owner key isRevoked : {}", isRevoked);
        if (isRevoked) {
            throw new SampleException(claimRequest.getKeyId() + " is revoked and can not be used.");
        }

        PublicKey publicKey = publicKeyProperty.getPublicKey();
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.fromName(claimRequest.getAlgorithm()));
        logger.debug("check public key of owner : {}", Hex.toHexString(algorithm.publicKeyToByte(publicKey)));
        // Check ownership of a DID
        Jwt.VerifyResult result = claimRequest.verify(publicKey);
        logger.debug("check ownership of DID : {}\n", result);

        if (!result.isSuccess()) {
            throw new SampleException("Authentication failed.\n" + result.getFailMessage());
        }

        logger.debug(" ### After authentication (Email, Sms)");
        // Assume that the issuer proceeds with a particular authentication
        logger.debug("Pass for test\n");

        // Check the type of Claims
        List<String> claimTypes = claimRequest.getClaimTypes();
        logger.debug("claimTypes :{}\n", claimTypes);

        // Assuming owner only requested a email claim
        Map claimMap = new HashMap();
        claimMap.put(claimTypes.get(0), "abc@icon.foundation");


        logger.debug(" ### Create credential (Email Claim)");
        // Create the credential object
        Credential credential = new Credential.Builder()
                .didKeyHolder(issuerKeyHolder)
                .nonce(claimRequest.getNonce())
                .build();

        logger.debug("types : {}", credential.getTypes());

        // Set the did of owner
        credential.setTargetDid(ownerDid);
        // Set the claims
        credential.setClaim(claimMap);
        logger.debug("claim : {}", credential.getClaim());

        // Set the validity period of the credential
        Date issued = new Date();
        long duration = credential.getDuration() * 1000L;  // to milliseconds for Date class
        Date expiration = new Date(issued.getTime() + duration);
        logger.debug("issue time:{} ~ expiration time:{}", issued, expiration);

        String signedCredential = issuerKeyHolder.sign(credential.buildJwt(issued, expiration));
        ;
        logger.debug("credential : {}\n", signedCredential);

        // Check the credential issued by issuer
        logger.debug(" ### Verify credential");
        credential = Credential.valueOf(signedCredential);
        String issuerDid = credential.getDid();
        logger.debug("did of issuer : {}", issuerDid);
        logger.debug("request credential nonce : {}", credential.getNonce());
        // Read the DID Document of issuer
        issuerDocument = didService.readDocument(issuerDid);
        logger.debug("check document of issuer : {}", issuerDocument.toJson());
        publicKeyProperty = issuerDocument.getPublicKeyProperty(credential.getKeyId());

        // Verify that publicKey of issuer is revoked
        isRevoked = publicKeyProperty.isRevoked();
        logger.debug("issuer key isRevoked : {}", isRevoked);
        if (isRevoked) {
            throw new SampleException(credential.getKeyId() + " is revoked and can not be used.");
        }

        publicKey = publicKeyProperty.getPublicKey();
        algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.fromName(credential.getAlgorithm()));
        logger.debug("check public key of issuer : {}", Hex.toHexString(algorithm.publicKeyToByte(publicKey)));
        // Check ownership of a DID
        result = Jwt.decode(signedCredential).verify(publicKey);
        logger.debug("check ownership of DID : {}", result);

        if (!result.isSuccess()) {
            throw new SampleException("Authentication failed.\n" + result.getFailMessage());
        }

        boolean checkTarget = ownerDid.equals(credential.getTargetDid());
        logger.debug("Check that the authentication target matches the owner did : {}",
                checkTarget);

        if (!checkTarget) {
            throw new SampleException("The owner's did and the issuer's target did differ.");
        }

        logger.debug("Types : {}", credential.getTypes());
        logger.debug("claim : {}\n", credential.getClaim());

        FileUtils.writeClaim(SampleConfig.CREDENTIAL_FILE_NAME, "credential", signedCredential);

        logger.debug(" ### The end");
    }
}
