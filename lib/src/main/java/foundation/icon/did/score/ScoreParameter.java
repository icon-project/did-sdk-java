package foundation.icon.did.score;

import com.google.gson.JsonObject;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.core.KeyProvider;
import foundation.icon.did.core.PropertyName;
import foundation.icon.did.document.Converters;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.document.PublicKeyProperty;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.DidService;
import foundation.icon.icx.KeyWallet;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is used to create transaction parameters that call a score function that
 * can use all the features of the DID document.
 */
public class ScoreParameter {

    private ScoreParameter() {
    }

    /**
     * Create a parameter for transaction that creates the DID Document.
     * {@linkplain DidService#create(KeyWallet, String)}
     *
     * @param keyProvider the KeyProvider object
     * @return the json string
     */
    public static String create(KeyProvider keyProvider, EncodeType encodeType) {
        PublicKeyProperty publicKeyProperty = createPublicKeyProperty(keyProvider, encodeType);
        return Converters.gson().toJson(publicKeyProperty);
    }

    /**
     * Create a parameter for transaction that update the DID Document. (add publicKey)
     * {@linkplain DidService#addPublicKey(KeyWallet, String)}
     *
     * @param didKeyHolder the DidKeyHolder object to use for authentication
     * @param keyProvider     the KeyProvider object to add
     * @param encodeType      the id of the publicKey to revoke
     * @return the Jwt object
     */
    public static Jwt addKey(DidKeyHolder didKeyHolder, KeyProvider keyProvider, EncodeType encodeType) {
        PublicKeyProperty publicKeyProperty = createPublicKeyProperty(keyProvider, encodeType);
        JsonObject jsonObject = Converters.gson().toJsonTree(publicKeyProperty).getAsJsonObject();

        Map<String, Object> map = new HashMap<>();
        map.put("id", didKeyHolder.getDid());
        map.put(PropertyName.KEY_DOCUMENT_PUBLICKEY, jsonObject);

        return new Jwt.Builder()
                .alg(didKeyHolder.getType().getName())
                .kid(didKeyHolder.getKid())
                .put(PropertyName.KEY_TX_UPDATE_METHOD, PropertyName.KEY_TX_UPDATE_METHOD_ADDKEY)
                .put(PropertyName.KEY_TX_UPDATE_PARAM, map)
                .build();
    }

    /**
     * Create a parameter for transaction that update the DID Document. (revoke publicKey)
     * {@linkplain DidService#revokeKey(KeyWallet, String)}
     *
     * @param didKeyHolder the DidKeyHolder object to use for authentication
     * @param revokeKeyId     revoke 할 public key 의 id
     * @return the jwt object
     */
    public static Jwt revokeKey(DidKeyHolder didKeyHolder, String revokeKeyId) {
        Map<String, String> param = new HashMap<>();
        param.put(PropertyName.KEY_DOCUMENT_ID, didKeyHolder.getDid());
        param.put(PropertyName.KEY_DOCUMENT_PUBLICKEY, revokeKeyId);
        return new Jwt.Builder()
                .alg(didKeyHolder.getType().getName())
                .kid(didKeyHolder.getKid())
                .put(PropertyName.KEY_TX_UPDATE_METHOD, PropertyName.KEY_TX_UPDATE_METHOD_REVOKEKEY)
                .put(PropertyName.KEY_TX_UPDATE_PARAM, param)
                .build();
    }

    private static PublicKeyProperty createPublicKeyProperty(KeyProvider keyProvider, EncodeType encodeType) {
        return new PublicKeyProperty.Builder()
                .id(keyProvider.getKeyId())
                .type(Collections.singletonList(keyProvider.getType().getIdentifier()))
                .publicKey(keyProvider.getPublicKey())
                .encodeType(encodeType)
                .build();
    }
}
