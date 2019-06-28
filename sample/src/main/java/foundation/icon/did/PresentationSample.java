package foundation.icon.did;


import foundation.icon.did.config.SampleConfig;
import foundation.icon.did.config.SampleKeys;
import foundation.icon.did.core.*;
import foundation.icon.did.document.Document;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.document.PublicKeyProperty;
import foundation.icon.did.exception.SampleException;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.jwt.Payload;
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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

@SuppressWarnings("Duplicates")
public class PresentationSample {

    private static Logger logger = LoggerFactory.getLogger(PresentationSample.class);

    public static void main(String[] args) throws Exception {

        // Create objects for connecting ICON Network
        SampleConfig config = SampleConfig.local();
        BigInteger networkId = config.getNetworkId();
        IconService iconService = config.iconService();

        // DID Document Score Address
        Address scoreAddress = config.getScoreAddress();

        // Create the DidService object
        DidService didService = new DidService(iconService, networkId, scoreAddress);

        logger.debug(" ### Check DID of owner");
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
        logger.debug("owner document : {}\n", ownerDocument.toJson());

        // Using issuer pk as a verifier
        logger.debug(" ### Check DID of verifier\n");
        KeyWallet verifierWallet = KeyWallet.load(new Bytes(SampleKeys.ISSUER_WALLET_PRIVATE_KEY));
        DidKeyHolder verifierKeyHolder = null;
        try {
            verifierKeyHolder = Keystore.loadDidKeyHolder(SampleConfig.TEST_PASSWORD, new File(SampleConfig.ISSUER_KEY_FILE_NAME));
        } catch (IOException e) {
            BigInteger balance = iconService.getBalance(verifierWallet.getAddress()).execute();
            if (balance.compareTo(IconAmount.of("1", IconAmount.Unit.ICX).toLoop()) < 0) {
                throw new SampleException("the balance of " + verifierWallet.getAddress() + " < 1 icx\n Use your KeyWallet");
            }

            Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
            KeyProvider keyProvider = algorithm.generateKeyProvider(SampleKeys.ISSUER_KEY_ID);
            System.out.println("pub:" + Hex.toHexString(algorithm.publicKeyToByte(keyProvider.getPublicKey())));
            System.out.println("priv:" + Hex.toHexString(algorithm.privateKeyToByte(keyProvider.getPrivateKey())));

            String json = ScoreParameter.create(keyProvider, EncodeType.BASE64);
            Document document = didService.create(verifierWallet, json);
            logger.debug("create verifier did : {}\n", document.getId());
            verifierKeyHolder = new DidKeyHolder.Builder(keyProvider)
                    .did(document.getId())
                    .build();
            Keystore.storeDidKeyHolder(SampleConfig.TEST_PASSWORD, verifierKeyHolder, SampleConfig.ISSUER_KEY_FILE_NAME);
        }

        // Verifier requests the owner for a presentation
        logger.debug(" ### Create Request presentation");
        String ownerDid = ownerKeyHolder.getDid();
        String nonce = Hex.toHexString(AlgorithmProvider.secureRandom().generateSeed(4));
        ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.PRESENTATION)
                .didKeyHolder(verifierKeyHolder)
                .responseId(ownerDid)
                .requestClaimTypes(Arrays.asList("email"))
                .nonce(nonce)
                .build();
        String signedRequest = verifierKeyHolder.sign(request.getJwt());
        logger.debug("jwt : {}\n", signedRequest);


        logger.debug(" ### Check Request from verifier");
        request = ClaimRequest.valueOf(signedRequest);
        // Make sure it is owner own request.
        logger.debug("REQ_PRSENTATION Info");
        logger.debug("  type:{}", request.getTypes());
        logger.debug("  requestId:{}", request.getRequestId());
        logger.debug("  responseId:{}", request.getResponseId());
        logger.debug("  request date:{}", request.getRequestDate());
        logger.debug("  nonce:{}", request.getNonce());
        if (!request.getResponseId().equals(ownerKeyHolder.getDid())) {
            throw new SampleException("This request is not for me.");
        }

        // Check the type of claims requested
        logger.debug("request claims types:{}\n", request.getClaimTypes());

        logger.debug(" ### Check credential");
        // Check the credential issued by issuer
        String signedCredential = null;
        try {
            signedCredential = FileUtils.loadClaim(SampleConfig.CREDENTIAL_FILE_NAME, "credential");
        } catch (FileNotFoundException e) {
            throw new SampleException("You need to run CredentialSample.");
        }
        // Assuming verifier only requested a email claim
        logger.debug("credential : {}\n", signedCredential);

        logger.debug(" ### Create presentation");
        // Create a presentation object
        // Set the nonce received from req_presentation
        Presentation presentation = new Presentation.Builder()
                .didKeyHolder(ownerKeyHolder)
                .nonce(request.getNonce())
                .build();

        // Add credentials issued by issuer
        presentation.addCredential(signedCredential);
        // Signs is with the given algorithm and Encodes to base64
        // default expiration time of presentation  : 5 minute
        String signedPresentation = ownerKeyHolder.sign(presentation.buildJwt());
        logger.debug("presentation : {}\n", signedPresentation);

        logger.debug(" ### Verify presentation of owner");
        presentation = Presentation.valueOf(signedPresentation);
        logger.debug("Types : {}", presentation.getTypes());
        logger.debug("nonce : {}\n", presentation.getNonce());
        ownerDid = presentation.getDid();
        logger.debug("check did of owner : {}", ownerDid);
        // Read a DID Document of owner
        ownerDocument = didService.readDocument(ownerDid);
        logger.debug("check document of owner : {}", ownerDocument.toJson());

        // Verify that the publicKey of owner is revoked
        PublicKeyProperty publicKeyProperty = ownerDocument.getPublicKeyProperty(presentation.getKeyId());
        boolean isRevoked = publicKeyProperty.isRevoked();
        logger.debug("owner key isRevoked : {}", isRevoked);
        if (isRevoked) {
            throw new SampleException(presentation.getKeyId() + " is revoked and can not be used.");
        }

        PublicKey publicKey = publicKeyProperty.getPublicKey();
        Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.fromName(presentation.getAlgorithm()));
        logger.debug("check public key of owner : {}", Hex.toHexString(algorithm.publicKeyToByte(publicKey)));
        // Check ownership of a DID
        Jwt.VerifyResult result = Jwt.decode(signedPresentation).verify(publicKey);
        logger.debug("check ownership of owner DID : {}\n", result);

        // Comparison of nonce of verifier and owner
        logger.debug("check nonce of request_presentation and presentation : {}\n", nonce.equals(presentation.getNonce()));


        logger.debug(" ### Verify credential of issuer");
        // Get claims from owner
        List<String> claims = presentation.getCredentials();
        for (String s : claims) {
            Payload payload = Jwt.decode(s).getPayload();
            logger.debug("issue date : {}", payload.getIat());
            logger.debug("expire date : {}", payload.getExp());
            logger.debug("nonce : {}", payload.getNonce());
            Credential credential = Credential.valueOf(s);

            String issuerDid = credential.getDid();
            logger.debug("check did of issuer : {}", issuerDid);
            // Get the DID Document of issuer
            Document issuerDocument = didService.readDocument(issuerDid);
            logger.debug("check document of issuer : {}", issuerDocument.toJson());

            // Verify that the publicKey is revoked
            publicKeyProperty = issuerDocument.getPublicKeyProperty(credential.getKeyId());
            isRevoked = publicKeyProperty.isRevoked();
            logger.debug("owner key isRevoked : {}", isRevoked);
            if (isRevoked) {
                throw new SampleException(credential.getKeyId() + " is revoked and can not be used.");
            }

            publicKey = publicKeyProperty.getPublicKey();
            algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.fromName(credential.getAlgorithm()));
            logger.debug("check public key of issuer : {}", Hex.toHexString(algorithm.publicKeyToByte(publicKey)));
            // Check DID ownership and expiration
            result = Jwt.decode(s).verify(publicKey);
            logger.debug("check ownership of issuer DID : {}", result);

            if (!result.isSuccess()) {
                throw new SampleException("Authentication failed.\n" + result.getFailMessage());
            }

            boolean checkTarget = ownerDid.equals(credential.getTargetDid());
            logger.debug("Check that the authentication target matches the owner did : {}",
                    checkTarget);

            if (!checkTarget) {
                throw new SampleException("The owner's did and the issuer's target did differ.");
            }

            logger.debug("claim Type : {}", credential.getTypes());
            logger.debug("claim : {}\n", credential.getClaim());
        }

        logger.debug(" ### The end");

    }
}
