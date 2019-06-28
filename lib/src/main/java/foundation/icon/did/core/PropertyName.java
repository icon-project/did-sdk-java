package foundation.icon.did.core;

public class PropertyName {

    private PropertyName() {
    }

    public static final String ALGO_KEY_RSA = "RS256";
    public static final String ALGO_KEY_ECDSA = "ES256";
    public static final String ALGO_KEY_ECDSAK = "ES256K";

    public static final String EC_CURVE_PARAM_SECP256R1 = "secp256r1";
    public static final String EC_CURVE_PARAM_SECP256K1 = "secp256k1";

    public static final String KEY_DOCUMENT_CONTEXT = "@context";
    public static final String KEY_DOCUMENT_ID = "id";
    public static final String KEY_DOCUMENT_CREATED = "created";
    public static final String KEY_DOCUMENT_UPDATED = "updated";
    public static final String KEY_DOCUMENT_PUBLICKEY = "publicKey";
    public static final String KEY_DOCUMENT_PUBLICKEY_ID = "id";
    public static final String KEY_DOCUMENT_PUBLICKEY_TYPE = "type";
    public static final String KEY_DOCUMENT_PUBLICKEY_HEX = "publicKeyHex";
    public static final String KEY_DOCUMENT_PUBLICKEY_BASE64 = "publicKeyBase64";
    public static final String KEY_DOCUMENT_PUBLICKEY_CREATED = "created";
    public static final String KEY_DOCUMENT_PUBLICKEY_REVOKED = "revoked";
    public static final String KEY_DOCUMENT_AUTHENTICATION = "authentication";
    public static final String KEY_DOCUMENT_AUTHENTICATION_PUBLICKEY = "publicKey";
    public static final String KEY_DOCUMENT_AUTHENTICATION_TYPE = "type";

    public static final String VALUE_DOCUMENT_CONTEXT = "https://w3id.org/did/v1";

    // Update Transaction
    public static final String KEY_TX_UPDATE_METHOD = "method";
    public static final String KEY_TX_UPDATE_METHOD_ADDKEY = "addKey";
    public static final String KEY_TX_UPDATE_METHOD_REVOKEKEY = "revokeKey";
    public static final String KEY_TX_UPDATE_PARAM = "param";

}
