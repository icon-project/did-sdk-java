# Changelog

## 0.8.3 (2019-5-15)
- Remove CryptoUtils class
- Move EncodeType class to upper level

## 0.8.2 (2019-5-14)
- Change to use encoded token string instead of signature in Jwt class

## 0.8.1 (2019-5-3)
- Move generateKeyPair method to Algorithm object

## 0.8.0 (2019-5-2)
- Remove korean text in code
- rename package : com.nomadconnection.icondid => foundation.icon.did
- rename files
   old : DidOperationFactory, DidClaim, IClaim, DidRegistryScore
   new : ScoreParameter, IssuerDid, ConvertJwt, DidScore
- Add DidKeyHolder class
- Move sign method of ConvertJwt to DidKeyHolder

## 0.7.3 (2019-4-23)
- DID Document create method 수정 : JWT format 에서 json object format 으로 변경
- deprecated method 제거 

## 0.7.2 (2019-3-26)
- DID Document 에서 hash property 제거 (createTxHash, updateTxHash) 
- JWT Header 에서 type property 제거
- credential, presentation 에 nonce property 추가
- Credential, Presentation 의 type 에 default value 추가 ("credential", "presentation")
- ClaimResponse class 제거
- ClaimRequest 의 requestClaims method param type 변경 (List -> Map)
- ClaimRequest 에 responseId 추가
- ClaimRequest 에 unsigned jwt 추가
- Document 의 publicKey type property 수정 (String -> List)
- DID Document 의 addKey method 수정
- Presentation 의 claims property 이름 변경 (claims -> credential)

## 0.6.1 (2019-3-21)
- ClaimRequest 추가 : Issuer 에게 Credential 요청, Owner 에게 Presentation 요청
- PublicKey 의 string encode type 은 BASE64 만 지원 (Hex 인 경우, score 에서 revert)
- Credential 과 Presentation 의 payload 수정
    - type 이 list 타입으로 변경
    - type 변경으로 credential 의 claim 추가 방법 변경 (기존 Credential.setClaim 메소드 변경)
- PublicKey 의 type 이름 변경 : Secp256k1VerificationKey 
- DID Document 의 created, updated, revoked 가 timestamp 에서 block height 으로 변경    

## 0.5.3 (2019-3-7)
- Change property in Authentication
- Add missing update properties  

## 0.5.2 (2019-2-27)
- icon-sdk-java version 업데이트
- ES256KAlgorithm sign/verify 할 때, DER format 인코딩/디코딩 제거
- DidOperationFactory class 추가 (DID CRUD 요청 생성)

## 0.5.1 (2019-1-30)
- public key revoke 체크 method 추가

## 0.5.0 (2019-1-29)
- ES256K Algorithm 추가
- 각 Algotihm 별 클래스 추가 (ES256Algorithm, RS256Algorithm) 
- Algorithm 클래스 AlgorithmProvider 로 변경
- ecdsa_verify 추가한 score 연동 테스트

## 0.4.0 (2019-1-24)
- `icon.did` 패키지 `core` 패키지로 변경
- PublicKeyProperty class 에서 사용하던 KeyProvider 제거
- KeyProvider 에 private key 추가
- Algorithm 클래스 추가 
- JwtUtils 클래스 제거
- Keystore 클래스 추가 (private key 와 did 저장)

## 0.3.0 (2019-1-22)

- JWT 로 score 호출 메소드 추가
- VerifyResult class 추가
- Jwt.verify 할 때, expiration time 확인 추가
- Jwt, JwtFactory `com.nomadconnection.icondid.jwt` 패키지 이동   

## 0.2.0 (2019-1-15)

- DidJwt 에서 Jwt 로 변경
- DidKeyPair 에서 KeyProvider 로 변경
- KeyProvider 에 PrivateKey 제거
- 패키지 구조 변경
- document 패키지 추가


## 0.1.1 (2018-12-24)

- public key `add`, `revoke` 추가 [5a44e36c](https://gitlab.com/did-vault/did-sdk-java/commit/5a44e36cad57b5319ba4ef3f3ff1ad65d64c0de9)
- New bicon-score : cxf847b8a788e2c978b57a8905fcdb7ed359b013a2