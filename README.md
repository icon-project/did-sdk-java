
## DID-SDK-JAVA

This SDK is used not only to create and manage `ICON DID`, but also to issue and verify `credentials` and `presentations`.

## Quick Guide
This section explains what kind of actions `owner`, `issuer`, and `verifier` typically perform in order to use `ICON DID`, and describes how to do them in a simple manner.

### Owner
An `owner` is able to keep his/her personal information on himself/herself without storing it on a remote server, thus keeping it secure.

The steps an `owner` must take are described below.
1. Generate a DID (See: [DID Document](#did-document)) 
1. Request a credential
    - The owner sends a credential request to an `issuer` to claim his credential. (See: [Credential Request](#credential-request))'
1. Generate a presentation 
    - When an `owner` receives a presentation request from a `verifier`, he responds back with a `presentation`. (See: [Presentation](#presentation))

### Issuer
An `issuer`, upon receiving a request from an `owner`, verifies the `owner`'s identity and provides a certificate.

The steps an `issuer` must take are described below
1. Generate a DID (See: [DID Document](#did-document))
1. Verify the credential request
    - Upon receiving a credential request from an `owner`, the `issuer` verifies the request and validates his claims. (See : [Verifying Requests](#request-verification))
1. Generate credentials
    - Upon successful validation, the `issuer` creates and sends the corresponding `credential` to the `owner`. (See: [Credential](#credential))

### Verifier
A `verifier` is an entity that requires certain information from an `owner` in order to provide service.

The steps a `verifier` must take are described below.
1. Generate a DID (See: [DID Document](#did-document))
    - Technically, not all `verifiers` must have its DID. If it doesn't have its DID, you can skip this step
1. Send a presentation request
    - The `verifier` sends a presentation request to an `owner`. The `verifier` may optionally sign the request before sending it (See: [Presentation request]((#requesting-presentation)))
1. Validate presentation
    - The `verifier` validates the `presentation` that an `owner` sent, and the `credentials` included inside it. (See: [presentation verification](#presentation-verification))

## DID Document
An `ICON DID` is managed on the ICON blockchain, and in order to create a DID and view or update its DID document, a transaction must be sent to a SCORE.

See: [ICON DID method specification](https://github.com/icon-project/icon-DID/blob/master/docs/ICON-DID-method.md)

This SDK can be used to create transactions that will be sent to a SCORE in order to create a DID and view or update its DID document.

### CreateDocument
Creates a new DID document.

In order to successfully create a DID document you will have to send a transaction that includes the following information to a SCORE.

- Information about the public key that will registered on the DID document (id, type, key, value)
- Data that is signed by a private key corresponding to the public key (in order to prove that the public key is appropriately owned)

##### KeyProvider

Key providers are objects that store information needed in order to create or modify DID documents

(As of version 0.9.1, SCOREs only support ES256K as the signing algorithm)
```java
// Information about the public key that will be registered on a DID document
String keyId = "ES256K-key";
// Information about the algorithm of the key
Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
// Generate a KeyProvider instance
KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);

```

##### DidService

In order to create a DID document on the blockchain, you must instantiate a `DIDService` object. 

You also need an `IconService` and `KeyWallet` instance in order to create a transaction. (Please refer to the documents of the ICON SDK)

```java
IconService iconService = new IconService(new HttpProvider("https://url"));
BigInteger networkId = new BigInteger("1");
Address scoreAddress = new Address("cx000...1");
KeyWallet wallet = KeyWallet.load(new Bytes("hx000...1"));
DidService didService = new DidService(iconService, networkId, scoreAddress);
```

After creating an instance of `DidService` and [KeyProvider](#keyprovider) respectively, you will be able to successfully send a transaction to a SCORE by calling `DidService.create`.

(As of version 0.9.1, SCOREs only support Base64 as the EncodeType)
```java
// Encoding type used to encode the string of the public key
PublicKeyProperty.EncodeType encodeType = PublicKeyProperty.EncodeType.BASE64;
// Create parameters that will be used when sending the DID registration request
String param = ScoreParameter.create(keyProvider, encodeType);
// Check results after registering a DID on the SCORE (on success, a DID document will be returned)
Document doc = didService.create(wallet, param);
doc.toJson();
// A DidKeyHolder object must be instantiated in order to use the DID
DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(document.getId())
                .build();
// Store the DidKeyHolder with a keystorefile
Keystore.storeDidKeyHolder(password, didKeyHolder, "did.json");
```

After the DID is successfully created on the SCORE, the newly-created `Document` will be transformed into a JSON string and returned like the example below.

```json
{
    "version": "1.0",
    "id": "did:icon:01:b2eb749fe08cf8185ae057d73a9ed7f963b4f2e0ae8655bd",
    "created": 529,
    "publicKey": [{
        "id": "ES256K-key",
        "type": ["Secp256k1VerificationKey"],
        "publicKeyBase64": "BIUG...=",
        "created": 529
    }],
    "authentication": [{
        "publicKey": "ES256K-key"
    }]
}
```

### readDocument

View a DID document by calling the `readDocument` function of a DidService instance. (See: [DidService instantiation](#didservice))

```java
String did = "did:icon:01:...1";
Document doc = didService.readDocument(did);
```

### addPublicKey

Add a public key to the already-created DID document (See: [Register DID document](#createdocument), [DidService instantiation](#didservice))

```java
// DID registered on the SCORE
String did = "did:icon:01:...1";

// Create DidKeyHolder to add public key
String authKeyId = "ES256K-key";
String privateKey = "...";	// base64
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));

// Either manually
DidKeyHolder didKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();
// Or by loading keystorefile
DidKeyHolder didKeyHolder = Keystore.loadDidKeyHolder(password, new File("did.json"));

// Generate new key
String keyId = "newKey";
Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);

// Create JWT needed in order to send a DID public key addition request to SCORE
Jwt jwt = ScoreParameter.addKey(
    didKeyHolder, keyProvider, EncodeType.BASE64);
// Create signed JWT
String signedJwt = didKeyHolder.sign(jwt);
// Send a public key addition request to SCORE, then check result
Document doc = didService.addPublicKey(wallet, signedJwt));
doc.toJson();
```

After the successful addition of a public key, the document will be returned in the form of a JSON string like the example below.

```json
{
    "version": "1.0",
    "id": "did:icon:01:b2eb749fe08cf8185ae057d73a9ed7f963b4f2e0ae8655bd",
    "created": 529,
    "publicKey": [{
        "id": "newKey",
        "type": ["Secp256k1VerificationKey"],
        "publicKeyBase64": "BMOg...=",
        "created": 530
    }, {
        "id": "ES256K-key",
        "type": ["Secp256k1VerificationKey"],
        "publicKeyBase64": "BIUG...=",
        "created": 529
    }],
    "authentication": [{
        "publicKey": "ES256K-key"
    }, {
        "publicKey": "newKey"
    }],
    "updated": 530
}
```

### RevokePublicKey

Revoke a certain public key on a DID document. Doing this will invalidate the public key, thus making it unable to be used any further.

```java
// DID that is registered on the SCORE
String did = "did:icon:01:...1";

// Create DidKeyHolder to revoke public key
String authKeyId = "ES256K-key";
String privateKey = "...";	// base64
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));

// Either manually,
DidKeyHolder didKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();
// Or by loading keystorefile
DidKeyHolder didKeyHolder = Keystore.loadDidKeyHolder(password, new File("did.json"));

// Id of the public key that we are aiming to revoke
String keyId = "newKey";

// Create JWT in order to revoke a DID public key
Jwt jwt = ScoreParameter.revokeKey(didKeyHolder, keyId);
String signedJwt = didKeyHolder.sign(jwt);
// Send a public key revocation request to SCORE, then check the result
Document doc = didService.revokeKeyJwt(wallet, signedJwt);
doc.toJson();
```

Upon a successful revocation of the public key, the document will be returned in the format below.

```json
{
    "version": "1.0",
    "id": "did:icon:01:b2eb749fe08cf8185ae057d73a9ed7f963b4f2e0ae8655bd",
    "created": 529,
    "publicKey": [{
        "id": "newKey",
        "type": ["Secp256k1VerificationKey"],
        "publicKeyBase64": "BMOg...=",
        "created": 530,
        "revoked": 531
    }, {
        "id": "ES256K-key",
        "type": ["Secp256k1VerificationKey"],
        "publicKeyBase64": "BIUG...=",
        "created": 529
    }],
    "authentication": [{
        "publicKey": "ES256K-key"
    }],
    "updated": 531
}
```

## Credential

After an `issuer` validates the claims of an `owner`, the `owner` can acquire the `credential` of the claims.

### Credential Request

In order to acquire a `credential`, an `owner` must send the following JWT to an `issuer`.

The DID used in this process must be already registered on the blockchain (See: [DID Document Registration](#createdocument), [DidService object instantiation](#didservice))

The following example creates a `DidClaim` object and issues a JWT.

```java

// DID of owner
String did = "did:icon:01:...1";

// DID of issuer
String issuerDid = "did:icon:01:...1";

// DID version
String version = "1.0";

// KeyId information of the public key that is registered on the DID document
String keyId = "owner";
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
// Private key corresponding to the public key
String privateKey = "...";	// base64
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder ownerKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();

// Claim type of credential that will be requested
Map claims = new HashMap();
claims.put("email", "abc@icon.foundation");

// Generate random nonce to use during request
String nonce = Hex.toHexString(AlgorithmProvider.secureRandom().generateSeed(4));

// Build instance of ClaimRequest
ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.CREDENTIAL)
    .didKeyHolder(ownerKeyHolder)
    .requestClaims(claims)
    .responseId(issuerDid)
    .nonce(nonce)    // (optional)
    .version(version)
    .build();
String requestJwt = ownerKeyHolder.sign(request.getJwt());
```

The created JWT is as follows. (See [JWT debugger](https://jwt.io))

```js
// header
{
  "alg": "ES256K",
  "kid": "did:icon:01:e96721825d09683be1438800e976ab498a0cf4fafca29316#owner"
}
// payload
{
    "version": "1.0",
    "iat": 1553582482,
    "iss": "did:icon:01:961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
    "requestClaim": {
      "email": "abc@icon.foundation"
    },
    "aud": "did:icon:01:961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
    "type": [
      "REQ_CREDENTIAL",
      "email"
    ]
}
// signature
```

### Request Verification

The request token created by an `owner` is validated using the method below. (See: [Credential Request](#credential_request))

The public key of the owner is required in the process of validating the token, and can be acquired by querying the blockchain. (See: [DidService instantiation](#didservice))

```java
// JWT received from the owner
String token = "eyJ0eXA..";

// Using the token, create an instance of ClaimRequest 
ClaimRequest claimRequest = ClaimRequest.valueOf(token);
logger.debug("REQ_CREDENTIAL Info");
logger.debug("  type : {}", claimRequest.getTypes());
logger.debug("  claims : {}", claimRequest.getClaims());
logger.debug("  requestId : {}", claimRequest.getRequestId());
logger.debug("  responseId : {}", claimRequest.getResponseId());
logger.debug("  request date : {}", claimRequest.getRequestDate());
logger.debug("  nonce : {}\n", claimRequest.getNonce());

// Extract the Did and public key id of the Owner
String did = claimRequest.getDid();
String keyId = claimRequest.getKeyId();

// Query the public key from the blockchain
Document ownerDocument = didService.readDocument(did);
PublicKeyProperty publicKeyProperty = ownerDocument.getPublicKeyProperty(keyId);

// Check if the public key of the owner has been revoked. If it has, return error
boolean isRevoked = publicKeyProperty.isRevoked();

PublicKey publicKey = publicKeyProperty.getPublicKey();
// Check signature
Jwt.VerifyResult verifyResult = claimRequest.verify(publicKey);
verifyResult.isSuccess();
verifyResult.getFailMessage();
```

### Credential

After an issuer successfully validates a request from an owner, the issuer can issue a set of `credential` to the owner, which has the owner's DID and recently validated information embedded inside of it. Also, the issuer's DID must already be registered on the blockchain before this step can proceed. (See: [DID Document Registration](#createdocument))

The `credential` can be only be created after instantiating a `KeyProvider` that contains the issuer's DID information.

```java
// DID of the issuer
String did = "did:icon:01:...1";

// Information about the public key used in the DID document
String keyId = "EmailIssuer";
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
// private key corresponding to the public key
String privateKey = "...";	// base64
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder issuerKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();

ClaimRequest claimRequest = ..;	// owner로부터 받은 request object

// Create Credential instance
Credential credential = new Credential.Builder()
    .didKeyHolder(issuerKeyHolder)
    .nonce(claimRequest.getNonce())  // (optional)
    .build();
```

Add the owner's DID and its claims to the `credential` and issue a JWT.

```java
// Configure owner's DID and credentials
String ownerDid = "did:icon:01:...1";
credential.setTargetDid(ownerDid);
credential.setVersion(version);
credential.addClaim("email", "abc@icon.foundation");

// Set expiration date
Date issued = new Date();
// Default settings
long duration = credential.getDuration() * 1000L;  // to milliseconds (for Date class)
Date expiration = new Date(issued.getTime() + duration);
// Issue the signed credential token
String token = issuerKeyHolder.sign(credential.buildJwt(issued, expiration));
```

The token is as follows. (See: [JWT debugger](https://jwt.io))

```js
// header
{
  "alg": "ES256K",
  "kid": "did:icon:01:849625146b531abdff5c0f87acd8d1c20f927c8f7ecd96c3#EmailIssuer"
}
// payload
{
    "version": "1.0",
    "claim": {
      "email": "abc@icon.foundation"
    },
    "exp": 1553667802,
    "iat": 1553581402,
    "iss": "did:icon:01:12802a771fa8f74d716366c170632010850587d56788cd76",
    "sub": "did:icon:01:5ea58f6949183cb9ba996f512f3ab56c2d88f0e459dd3f33",
    "type": [
      "CREDENTIAL",
      "email"
    ]
  }
// signature
```

## Presentation

A `presentation` including `credential` is signed and produced. The `credential` can then be provided to a `verifier`.

### Requesting Presentation

A `verifier` can request a `presentation` by following the steps depicted below.

```java
// DID of an owner the verifier is sending the request to
String ownerDid = "did:icon:01:...1";
Date requestDate = new Date();
// Credentials that the verifier wishes to verify
List<String> claimTypes = Arrays.asList("email");

// If the verifier does not have a DID
ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.PRESENTATION)
                .algorithm(AlgorithmProvider.Type.NONE)
                .responseId(ownerDid)
                .requestDate(requestDate)
                .requestClaimTypes(claimTypes)
                .version(version)
                .build();
// Unsigned JWT
String unsigendJwt = request.compact();

// If the verifier has an existing DID
String keyId = "verifier";
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
// Private key corresponding to the public key
String privateKey = "...";	// base64
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder verifierKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();

// Create random nonce that will be used when sending request
String nonce = Hex.toHexString(AlgorithmProvider.secureRandom().generateSeed(4));

ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.PRESENTATION)
                .didKeyHolder(verifierKeyHolder)
                .responseId(ownerDid)
                .requestDate(requestDate)
                .requestClaimTypes(claimTypes)
      			.nonce(nonce)
      			.version(version)
                .build();
// Signed JWT
String sigendJwt = verifierKeyHolder.sign(request.getJwt());
```

The resulting token is as follows. (See: [JWT debugger](https://jwt.io))

```json
// header
{
  "alg": "none"
}
// payload
{
    "version": "1.0",
    "iat": 1553583104,
    "iss": "did:icon:01:12802a771fa8f74d716366c170632010850587d56788cd76",
    "aud": "did:icon:01:5ea58f6949183cb9ba996f512f3ab56c2d88f0e459dd3f33",
    "type": [
      "REQ_PRESENTATION",
      "email"
    ]
  }
```



### Presentation

When a `verifier` requests certain `credentials` from an `owner`, the `owner` creates a `presentation` corresponding to the requested `credentials` and provides it to the `verifier`.

```java
// DID of owner
String did = "did:icon:01:...1";

// Info of public key registered on DID document
String keyId = "owner";
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;

// Private key corresponding to the public key
String privateKey = "...";	// base64
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder ownerKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();

// Request object that the verifier has sent
ClaimRequest claimRequest = ..;

// Create presentation instance
Presentation presentation = new Presentation.Builder()
                .didKeyHolder(ownerKeyHolder)
		      	.nonce(request.getNonce())
		      	.version(version)
                .build();

```

Add the owner's claims and issue a JWT


```java
// Credential token the the issuer has sent
String credential = "eyJ0eXA...";

// Add credential
presentation.addCredential(credential);

// The default expiration time of a presentation token is 5 minutes (in order to prevent malicious requests)
// Issue a signed presentation token
String token = ownerKeyHolder.sign(presentation.buildJwt());
```

The JWT is as follows. (See: [JWT debugger](https://jwt.io))

```js
// header
{
  "typ": "JWT",
  "alg": "ES256K",
  "kid": "did:icon:01:e96721825d09683be1438800e976ab498a0cf4fafca29316#owner"
}
// payload
{
    "version": "1.0",
    "credential": [
      "eyJhb...E"
    ],
    "exp": 1553586450,
    "iat": 1553586150,
    "iss": "did:icon:01:5ea58f6949183cb9ba996f512f3ab56c2d88f0e459dd3f33",
    "type": [
      "PRESENTATION",
      "email"
    ]
  }
// signature
```

### Presentation Verification

A verifier can verify the presentation it has received from a owner using the following methods. (See: [Register presentation](#presentation))

The `verifier` must verify both the presentation token that the `owner` has issued and the credentials that an `issuer` has issued that is embedded inside the `owner`'s token.

The public keys of the owner and issuer are required in order to verify the token. These public keys can be viewed by querying the blockchain. (See: [DidService instantiation](#didservice));

The below steps should be followed to verify the token that an `owner` has sent.

```java
// JWT that the owner has sent
String token = "eyJ0eX...";

// Create presentation instance using the token
Presentation presentation = Presentation.valueOf(token);

// Extract DID and public key id of the owner
String ownerDid = presentation.getDid();
String ownerKeyId = presentation.getKeyId();

// Query the public key from the blockchain
Document ownerDocument = didService.readDocument(ownerDid);

// Confirm the public key of the owner has been revoked
PublicKeyProperty publicKeyProperty = ownerDocument.getPublicKeyProperty(ownerKeyId);
// If public key of the owner has been revoked, return error (revoke: true)
boolean isRevoked = publicKeyProperty.isRevoked();

PublicKey publicKey = publicKeyProperty.getPublicKey();

// Verify results
Jwt.VerifyResult verifyResult = Jwt.decode(token).verify(publicKey);
verifyResult.isSuccess();
verifyResult.getFailMessage();
```

Verify the `credential` that is embedded inside the `presentation` token

```java

// DID of the owner that sent the presentation token
String ownerDid = "...owner did...";

// Extract credentials
List<String> claims = credential.getClaims();
for (String credentialJwt : claims) {
    // Create Credential instance using the token
    Credential credential = Credential.valueOf(credentialJwt);
    // Extract DID and public key id of the issuer
    String issuerDid = credential.getDid();
    String issuerKeyId = credential.getKeyId();
    
    // Query the public key of the issuer from the blockchain
    Document issuerDocument = didService.readDocument(issuerDid);

    // Check if the public key of the owner has been revoked
    PublicKeyProperty publicKeyProperty = issuerDocument.getPublicKeyProperty(issuerKeyId);
    // If public key has been revoked, return error (revoke: true)
    boolean isRevoked = publicKeyProperty.isRevoked();
    
    PublicKey publicKey = publicKeyProperty.getPublicKey();

    Jwt.VerifyResult verifyResult = Jwt.decode(credentialJwt).verify(publicKey);
    verifyResult.isSuccess();
    verifyResult.getFailMessage();
    
    // Check if owner's DID equals the subject that the issuer has verified
    boolean checkTarget = ownerDid.equals(credential.getSubject());
}
```

After validating the owner and issuer, the verified claims can be viewed by extracting them from the `credential` object.

```java
// Extract credential type
String type = credential.getType();
// Check claims
Map<String, Object> claim = credential.getClaim();
```



## References

- [did-java-sample](https://repo.theloop.co.kr/theloop/did-java-sample)



## Sample

- [sample project](./sample/README.md)



## Version

0.8.3 (beta)




## Download

Download [the latest JAR](https://drive.google.com/open?id=1S8MK9w9ae9snXAtISXRKxjbFPvl4MXmu)

Add dependencies

```gradle
implementation "foundation.icon:icon-sdk:0.9.11"
implementation "com.google.code.gson:gson:2.8.0"
implementation "org.bouncycastle:bcprov-jdk15on:1.60"
```



