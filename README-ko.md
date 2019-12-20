[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

## DID-SDK-JAVA

`ICON DID`를 생성/관리하고 `credential`, `presentation`을 발급하고 검증하기 위한 SDK입니다.

## Quick Guide
`ICON DID`를 이용하기 위해 `owner`, `issuer`, `verifier` 입장에서 각각 어떤 작업들을 수행하고, 이것을 어떻게 해야 하는지 간략하게 소개합니다.

### Owner
`owner`는 개인의 정보를 다른 서버에 저장하지 않고 본인이 직접 가지고 있음으로써 자신의 개인정보를 보호할 수 있습니다.
 
`owner`가 해야 하는 작업과 그 방법은 다음과 같습니다. 
1. DID 생성 (참고: [DID Document](#did-document))    
1. Credential request 생성
    - 인증 요청을 해당 `issuer`에게 보내어 신원 인증을 받습니다. (참고: [Credential Request](#credential-request))
1. Presentation 생성  
    - `verifier`에게 presentation request를 받으면, `owner`는 presentation을 생성해서 `verifier`에게 전달합니다. (참고: [Presentation](#presentation)) 

### Issuer
`issuer`는 신원주의 요청에 따라, 신원을 인증하고 증명서를 발급해 줍니다.

`issuer`가 해야 하는 작업과 그 방법은 다음과 같습니다. 
1. DID 생성 (참고: [DID Document](#did-document))  
1. Credential request 검증  
    - `owner`에게서 받은 인증 요청(credential request)에 대해서 정상적인 `owner`로부터 요청받은 것인지 검증합니다. (참고: [Request Verification](#request-verification))
1. Credential 생성  
    - 인증을 완료했다면, 이에 대한 `credential`을 생성해 줍니다. (참고: [Credential](#credential))

### Verifier
`verifier`는 서비스 제공을 위해 개인정보를 필요로 하는 주체이며, `owner`에게 인증서를 제공받아 검증합니다.

`verifier`가 해야 하는 작업과 그 방법은 다음과 같습니다. 
1. DID 생성(참고: [DID Document](#did-document))  
    - 기술적으로 `verifier`의 경우에는 DID가 반드시 필요한 것은 아닙니다. DID가 필요한 경우라면, DID를 생성합니다.
1. Presentation request 생성  
    - `verifier`가 `owner`에게 `presentation`을 요청할 때 request presentation을 `owner`에게 전달합니다. 이 때 `verifier`는 서명을 하여 전달하거나, 서명없이 전달하는 두 가지 방법이 있습니다. (참고: [Presentation Request](#presentation-request))
1. Presentation 검증
    - `verifier`는 `owner`에게 받은 `presentation`과 그 안에 포함된 `credential`을 검증합니다. (참고: [Presentation Verification](#presentation-verification))

## DID Document

`ICON DID`는 ICON blockchain 상에서 관리되며 등록 및 수정을 위해서는 SCORE에 transaction을 전송해야 합니다. 

참고: [ICON DID method specification](https://github.com/icon-project/icon-DID/blob/master/docs/ICON-DID-method.md)

SDK를 이용하여 DID document 등록/수정에 필요한 transaction 데이터를 구성해 SCORE에 전송할 수 있고, 등록된 DID document를 조회할 수 있습니다.


### CreateDocument

새로운 DID document를 생성합니다.

DID document를 등록하기 위해서는 SCORE에 다음의 정보들을 포함한 transaction을 전송해야 합니다.

- DID document에 등록할 public key 정보 (id, type, key value)
- public key에 대응하는 private key로 서명한 데이터 (public key 소유 증명)

##### KeyProvider

DID document 등록 및 수정에 필요한 정보를 보관하는 객체 생성

(SCORE에서는 서명 algorithm으로 ES256K만 지원합니다. - SCORE version: 0.9.1)

```java
// did document에 등록할 public key에 대한 정보
String keyId = "ES256K-key";
// 보관할 key의 algorithm 정보
Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
// key provider 객체 생성 
KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);

```

##### DidService

Blockchain에 DID document를 등록하기 위해서 `DIDService` 객체를 생성합니다. 

Transaction을 전송하기 위해서 `IconService`와 `KeyWallet`객체가 필요합니다. (ICON-SDK-JAVA)

```java
IconService iconService = new IconService(new HttpProvider("https://url"));
BigInteger networkId = new BigInteger("1");
Address scoreAddress = new Address("cx000...1");
KeyWallet wallet = KeyWallet.load(new Bytes("hx000...1"));
DidService didService = new DidService(iconService, networkId, scoreAddress);
```

`DidService`와 [KeyProvider](#keyprovider) 객체를 생성한 후, `DidService.create`를 호출하면 SCORE에 transaction을 전송합니다.

(SCORE에서 EncodeType으로 BASE64만 지원합니다. - SCORE version: 0.9.1)

```java
// public key의 string을 인코딩 방식 (Hex, Base64)
PublicKeyProperty.EncodeType encodeType = PublicKeyProperty.EncodeType.BASE64;
// SCORE에 DID 등록 요청을 위한 parameter string 생성
String param = ScoreParameter.create(keyProvider, encodeType);
// SCORE 등록 요청 후, 결과 확인 (성공하면 DID document를 return)
Document doc = didService.create(wallet, param);
doc.toJson();	// return json string
// DID를 사용하기 위한 DidKeyHolder 생성하기
DidKeyHolder didKeyHolder = new DidKeyHolder.Builder(keyProvider)
                .did(document.getId())
                .build();
// DidKeyHolder를 keystorefile 로 저장하기
Keystore.storeDidKeyHolder(password, didKeyHolder, "did.json");
```

SCORE에서 DID 생성 및 등록에 성공하면 다음의 json string을 변환한 `Document`객체를 리턴합니다.

```json
{
    "@context": "https://w3id.org/did/v1",
    "id": "did:icon:0000b2eb749fe08cf8185ae057d73a9ed7f963b4f2e0ae8655bd",
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



### ReadDocument

DidService의 `readDocument`를 호출해 등록된 DID의 document를 조회합니다. (참고: [DidService 객체 생성](#didservice))

```java
String did = "did:icon:0000...1";
Document doc = didService.readDocument(did);
```



### AddPublicKey

등록한 DID document에 public key를 추가합니다. (참고: [DID Document 등록](#createdocument), [DidService 객체 생성](#didservice))

```java
// SCORE에 등록된 did
String did = "did:icon:0000...1";

// publickey 추가를 위한 인증 가능한 DidKeyHolder 생성
String authKeyId = "ES256K-key";
String privateKey = "...";	// base64
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder didKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();
// or keystorefile load
DidKeyHolder didKeyHolder = Keystore.loadDidKeyHolder(password, new File("did.json"));

// 새로운 key 생성
String keyId = "newKey";
Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);

// SCORE에 DID publickey 를 추가 요청하기 위한 JWT 객체 생성
Jwt jwt = ScoreParameter.addKey(
    didKeyHolder, keyProvider, EncodeType.BASE64);
// 서명한 JWT 생성
String signedJwt = didKeyHolder.sign(jwt);
// SCORE에 public key 추가 요청 후, 결과 확인
Document doc = didService.addPublicKey(wallet, signedJwt));
doc.toJson();	// return json string
```

Public key 추가에 성공하면 document가 리턴되고 SCORE에서 조회한 json string은 다음과 같습니다.

```json
{
    "@context": "https://w3id.org/did/v1",
    "id": "did:icon:0000b2eb749fe08cf8185ae057d73a9ed7f963b4f2e0ae8655bd",
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

DID document에서 public key를 revoke합니다. Revoke를 하게 되면 해당 public key는 더 이상 유효하지 않습니다.

```java
// SCORE에 등록된 did
String did = "did:icon:0000...1";

// publickey revoke 하기 위한 인증 가능한 DidKeyHolder 생성
String authKeyId = "ES256K-key";
String privateKey = "...";	// base64
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder didKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();
// or keystorefile load
DidKeyHolder didKeyHolder = Keystore.loadDidKeyHolder(password, new File("did.json"));

// revoke할 public key id
String keyId = "newKey";

// DID publickey revoke 요청을 위한 JWT 객체 생성
Jwt jwt = ScoreParameter.revokeKey(didKeyHolder, keyId);
String signedJwt = didKeyHolder.sign(jwt);
// SCORE에 public key revoke 요청 후, 결과 확인
Document doc = didService.revokeKeyJwt(wallet, signedJwt);
doc.toJson();	// return json string
```

Public key revoke에 성공하면 document가 리턴되고 결과는 다음과 같습니다.

```json
{
    "@context": "https://w3id.org/did/v1",
    "id": "did:icon:0000b2eb749fe08cf8185ae057d73a9ed7f963b4f2e0ae8655bd",
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

DID의 owner는 `issuer`로부터 claim 인증 진행 후, 인증에 대한 확인서 `credential`을 발급받을 수 있습니다.



### Credential Request

`credential`을 발급받기 위해서 owner는 다음의 JWT 토큰을 `issuer`에게 전달해야 합니다. 
이 때 사용하는 DID는 blockchain에 등록되어 있어야 합니다. (참고: [DID Document 등록](#createdocument), [DidService 객체 생성](#didservice))

다음과 같이 DID 정보를 포함한 `DidClaim` 객체를 생성하고 JWT 토큰을 발급합니다.

```java

// owner의 DID
String did = "did:icon:0000...1";

// issuer의 DID
String issuerDid = "did:icon:0000...1";

// DID document에 등록된 publickey 중 사용할 keyId 정보
String keyId = "owner";
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
// 사용할 publickey와 매칭되는 private key
String privateKey = "...";	// base64
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder ownerKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();

// 요청할 credential의 claim type
Map claims = new HashMap();
claims.put("email", "abc@icon.foundation");

// 요청 관리를 위한 random 한 nonce 생성
String nonce = Hex.toHexString(AlgorithmProvider.secureRandom().generateSeed(4));

// ClaimRequest 객체 생성
ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.CREDENTIAL)
    .didKeyHolder(ownerKeyHolder)
    .requestClaims(claims)
    .responseId(issuerDid)
    .nonce(nonce)    // (optional)
    .build();
String requestJwt = ownerKeyHolder.sign(request.getJwt());
```

생성된 토큰 정보는 다음과 같습니다.  (참고: [JWT debugger](https://jwt.io))

```js
// header
{
  "alg": "ES256K",
  "kid": "did:icon:0000e96721825d09683be1438800e976ab498a0cf4fafca29316#owner"
}
// payload
{
    "iat": 1553582482,
    "iss": "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
    "requestClaims": {
      "email": "abc@icon.foundation"
    },
    "sub": "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
    "type": [
      "REQ_CREDENTIAL",
      "email"
    ]
}
// signature
```



### Request Verification

위에서 owner가 생성한 토큰을 다음과 같이 검증합니다 (참고: [Credential Request](#credential_request))

토큰을 검증하기 위해서 필요한 owner의 public key는 blockchain에서 조회합니다. (참고: [DidService 객체 생성](#didservice))

```java
// Owner로부터 전달받은 JWT 토큰
String token = "eyJ0eXA..";

// 토큰으로부터 ClaimRequest 객체 생성
ClaimRequest claimRequest = ClaimRequest.valueOf(token);
logger.debug("REQ_CREDENTIAL Info");
logger.debug("  type : {}", claimRequest.getTypes());
logger.debug("  claims : {}", claimRequest.getClaims());
logger.debug("  requestId : {}", claimRequest.getRequestId());
logger.debug("  responseId : {}", claimRequest.getResponseId());
logger.debug("  request date : {}", claimRequest.getRequestDate());
logger.debug("  nonce : {}\n", claimRequest.getNonce());

// Owner의 DID와 publickey-id 호출
String did = claimRequest.getDid();
String keyId = claimRequest.getKeyId();

// blockchain에서 publicKey 조회
Document ownerDocument = didService.readDocument(did);
PublicKeyProperty publicKeyProperty = ownerDocument.getPublicKeyProperty(keyId);

// owner의 public key가 revoke됐는지 확인
// revoke된 publickey인 경우, 에러 리턴
boolean isRevoked = publicKeyProperty.isRevoked();

PublicKey publicKey = publicKeyProperty.getPublicKey();
// signature 확인
Jwt.VerifyResult verifyResult = claimRequest.verify(publicKey);
verifyResult.isSuccess();		// verify 성공 여부
verifyResult.getFailMessage();	// verify 실패 메시지 
```



### Credential

Issuer는 owner의 요청 확인에 성공하면 owner의 DID와 인증한 정보를 포함한 `credential`을 발급합니다. 
이때, issuer의 DID는 blockchain에 등록되어 있어야 합니다. (참고: [DID Document 등록](#createdocument))

Issuer의 DID 정보를 갖는 `KeyProvider` 객체를 생성 후, `credential` 객체를 생성합니다.

```java
// issuer의 DID
String did = "did:icon:0000...1";

// DID document에 등록된 publickey에 대한 정보
String keyId = "EmailIssuer";
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
// 사용할 publickey와 매칭되는 private key
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

// Credential 객체 생성
Credential credential = new Credential.Builder()
    .didKeyHolder(issuerKeyHolder)
    .nonce(claimRequest.getNonce())  // (optional)
    .build();
```

`credential`에 owner의 DID와 인증 정보를 추가하고 JWT 토큰을 발급합니다.

```java
// Owner의 DID와 인증 정보를 셋팅
String ownerDid = "did:icon:0000...1";
credential.setTargetDid(ownerDid);
credential.addClaim("email", "abc@icon.foundation");

// 인증 유효기간 설정
Date issued = new Date();
// default 설정 정보
long duration = credential.getDuration() * 1000L;  // to milliseconds (for Date class)
Date expiration = new Date(issued.getTime() + duration);
// 서명한 credenetial 발급
String token = issuerKeyHolder.sign(credential.buildJwt(issued, expiration));
```

생성된 토큰 정보는 다음과 같습니다. (참고 : [JWT debugger](https://jwt.io))

```js
// header
{
  "alg": "ES256K",
  "kid": "did:icon:0000849625146b531abdff5c0f87acd8d1c20f927c8f7ecd96c3#EmailIssuer"
}
// payload
{
    "claim": {
      "email": "abc@icon.foundation"
    },
    "exp": 1553667802,
    "iat": 1553581402,
    "iss": "did:icon:000012802a771fa8f74d716366c170632010850587d56788cd76",
    "sub": "did:icon:00005ea58f6949183cb9ba996f512f3ab56c2d88f0e459dd3f33",
    "type": [
      "CREDENTIAL",
      "email"
    ]
  }
// signature
```



## Presentation

`credential`을 서명한 `presentation`을 생성해서 `verifier`에게 전달하여 사용할 수 있습니다.



### Presentation Request

`verifier`는 필요한 presentation을 다음과 같이 요청할 수 있습니다.

```java
// presentation을 요청할 사용자의 DID
String ownerDid = "did:icon:0000...1";
Date requestDate = new Date();
// 필요한 인증 정보
List<String> claimTypes = Arrays.asList("email");

// Verifier의 DID가 없는 경우
ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.PRESENTATION)
                .algorithm(AlgorithmProvider.Type.NONE)
                .responseId(ownerDid)
                .requestDate(requestDate)
                .requestClaimTypes(claimTypes)
                .build();
// 서명없는 JWT token
String unsigendJwt = request.compact();

// Verifier의 DID가 있는 경우
String keyId = "verifier";
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
// 사용할 publickey 와 매칭되는 private key
String privateKey = "...";	// base64
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder verifierKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();

// 요청 관리를 위한 random 한 nonce 생성
String nonce = Hex.toHexString(AlgorithmProvider.secureRandom().generateSeed(4));

ClaimRequest request = new ClaimRequest.Builder(ClaimRequest.Type.PRESENTATION)
                .didKeyHolder(verifierKeyHolder)
                .responseId(ownerDid)
                .requestDate(requestDate)
                .requestClaimTypes(claimTypes)
                .nonce(nonce)
                .build();
// 서명있는 JWT token
String sigendJwt = verifierKeyHolder.sign(request.getJwt());
```

생성된 서명없는 토큰 정보는 다음과 같습니다. (참고: [JWT debugger](https://jwt.io))

```json
// header
{
  "alg": "none"
}
// payload
{
    "iat": 1553583104,
    "iss": "did:icon:000012802a771fa8f74d716366c170632010850587d56788cd76",
    "sub": "did:icon:00005ea58f6949183cb9ba996f512f3ab56c2d88f0e459dd3f33",
    "type": [
      "REQ_PRESENTATION",
      "email"
    ]
  }
```



### Presentation

위에서 요청받은 credential에 대한 presentation을 생성해서 `verifier`에게 전달합니다.

```java
// owner의 DID
String did = "did:icon:0000...1";

// DID document에 등록된 publickey에 대한 정보
String keyId = "owner";
AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256;

// 사용할 publickey와 매칭되는 private key
String privateKey = "...";	// base64
Algorithm algorithm = AlgorithmProvider.create(type);
PrivateKey pk = algorithm.byteToPrivateKey(EncodeType.BASE64.decode(privateKey));
DidKeyHolder ownerKeyHolder = new DidKeyHolder.Builder()
                .did(did)
                .keyId(authKeyId)
                .type(type)
                .privateKey(pk)
                .build();

ClaimRequest claimRequest = ..;	// verifier 로부터 받은 Request object

// Presentation 객체 생성
Presentation presentation = new Presentation.Builder()
                .didKeyHolder(ownerKeyHolder)
                .nonce(request.getNonce())
                .build();

```

Owner의 claim 정보를 추가하고 JWT 토큰을 발급합니다.

```java
// issuer에게 받은 credential 토큰
String credential = "eyJ0eXA...";

// credential을 추가
presentation.addCredential(credential);

// presentation의 default expiration time은 5분 (도용방지)
// 서명한 presentation 토큰 발급
String token = ownerKeyHolder.sign(presentation.buildJwt());
```

생성된 토큰 정보는 다음과 같습니다.  (참고: [JWT debugger](https://jwt.io))

```js
// header
{
  "typ": "JWT",
  "alg": "ES256K",
  "kid": "did:icon:0000e96721825d09683be1438800e976ab498a0cf4fafca29316#owner"
}
// payload
{
    "credential": [
      "eyJhb...E"
    ],
    "exp": 1553586450,
    "iat": 1553586150,
    "iss": "did:icon:00005ea58f6949183cb9ba996f512f3ab56c2d88f0e459dd3f33",
    "type": [
      "PRESENTATION",
      "email"
    ]
  }
// signature
```



### Presentation Verification

Verifier는 owner에게 받은 presentation을 다음과 같이 검증합니다. (참고: [Presentation 등록](#presentation))
Verifier는 owner가 발급한 토큰과 토큰 안에 포함된 issuer가 발급한 토큰 둘 다 검증해야 합니다.
토큰을 검증하기 위해서 필요한 owner와 issuer의 public key는 blockchain에서 조회합니다. (참고: [DidService 객체 생성](#didservice))

Owner 가 보낸 토큰을 검증합니다.

```java
// owner로부터 받은 JWT 토큰
String token = "eyJ0eX...";

// 토큰의 정보를 토대로 presentation 객체 생성 
Presentation presentation = Presentation.valueOf(token);
// Owner의 DID와 publickey-id 호출
String ownerDid = presentation.getDid();
String ownerKeyId = presentation.getKeyId();

// blockchain에서 publicKey 조회
Document ownerDocument = didService.readDocument(ownerDid);

// owner의 public key가 revoke 됐는지 확인
PublicKeyProperty publicKeyProperty = ownerDocument.getPublicKeyProperty(ownerKeyId);
// revoke 된 publickey인 경우, 에러 리턴 (revoke: true)
boolean isRevoked = publicKeyProperty.isRevoked();

PublicKey publicKey = publicKeyProperty.getPublicKey();

// verify
Jwt.VerifyResult verifyResult = Jwt.decode(token).verify(publicKey);
verifyResult.isSuccess();		// verify 성공 여부
verifyResult.getFailMessage();	// verify 실패 메시지 
```

`presentation` 토큰에 포함된 issuer가 발급한 `credential`을 검증합니다.

```java
// 위에서 확인한 presentation 토큰을 전송한 owner의 did 
String ownerDid = "...owner did...";

// Credential 호출
List<String> claims = credential.getClaims();
for (String credentialJwt : claims) {
    // 토큰의 정보를 토대로 Credential 객체 생성 
    Credential credential = Credential.valueOf(credentialJwt);
    // Issuer의 DID와 publickey-id 호출
    String issuerDid = credential.getDid();
    String issuerKeyId = credential.getKeyId();
    
    // blockchain에서 issuer의 publicKey 조회
    Document issuerDocument = didService.readDocument(issuerDid);

    // owner의 public key가 revoke 됐는지 확인
    PublicKeyProperty publicKeyProperty = issuerDocument.getPublicKeyProperty(issuerKeyId);
    // revoke된 publickey인 경우, 에러 리턴 (revoke: true)
    boolean isRevoked = publicKeyProperty.isRevoked();
    
    PublicKey publicKey = publicKeyProperty.getPublicKey();
    // verify
    Jwt.VerifyResult verifyResult = Jwt.decode(credentialJwt).verify(publicKey);
    verifyResult.isSuccess();		// verify 성공 여부
    verifyResult.getFailMessage();	// verify 실패 메시지 
    
    // issuer가 인증한 대상과 owner의 DID가 일치하는지 확인
    boolean checkTarget = ownerDid.equals(credential.getSubject());
}
```

Owner와 issuer 검증 후, `credential` 객체에서 인증한 정보에 대해서 조회할 수 있습니다.

```java
// 인증 타입 확인
String type = credential.getType();
// 인증 정보 확인
Map<String, Object> claim = credential.getClaim();
```



## References

- [did-java-sample](https://repo.theloop.co.kr/theloop/did-java-sample)




## Sample

- [sample project](./sample/README.md)



## Version

0.8.3 (beta)




## Download

Download [the latest JAR](https://github.com/icon-project/did-sdk-java/raw/master/lib/build/libs/icon-did-0.8.6.jar)

dependency 추가

```gradle
implementation "foundation.icon:icon-sdk:0.9.11"
implementation "com.google.code.gson:gson:2.8.0"
implementation "org.bouncycastle:bcprov-jdk15on:1.60"
```



