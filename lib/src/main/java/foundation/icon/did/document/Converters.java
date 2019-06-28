package foundation.icon.did.document;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.PropertyName;
import foundation.icon.did.exceptions.KeyPairException;
import foundation.icon.did.exceptions.ResolveException;
import foundation.icon.did.jwt.Payload;

import java.lang.reflect.Type;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Converters {

    private static Gson GSON;

    private static Gson create() {
        GsonBuilder builder = new GsonBuilder();
        builder.registerTypeAdapter(Long.class, new LongSerializer());
        builder.registerTypeAdapter(Payload.class, new PayloadSerializer());
        builder.registerTypeAdapter(Payload.class, new PayloadDeserializer());
        builder.registerTypeAdapter(Document.class, new DocumentDeserializer());
        builder.registerTypeAdapter(Document.class, new DocumentSerializer());
        builder.registerTypeAdapter(PublicKeyProperty.class, new PublicKeyDeserializer());
        builder.registerTypeAdapter(PublicKeyProperty.class, new PublicKeySerializer());
        builder.registerTypeAdapter(AuthenticationProperty.class, new AuthenticationDeserializer());
        builder.disableHtmlEscaping();
        return builder.create();
    }

    public static Gson gson() {
        if (GSON == null) {
            GSON = create();
        }
        return GSON;
    }

    public static class LongSerializer implements JsonSerializer<Long> {
        @Override
        public JsonElement serialize(Long src, Type typeOfSrc, JsonSerializationContext context) {
            if (src == 0) return null;
            return new JsonPrimitive(src);
        }
    }

    public static class PayloadSerializer implements JsonSerializer<Payload> {
        @Override
        public JsonElement serialize(Payload src, Type typeOfSrc, JsonSerializationContext context) {
            return gson().toJsonTree(src.getMap()).getAsJsonObject();
        }
    }

    public static class PayloadDeserializer implements JsonDeserializer<Payload> {
        @Override
        public Payload deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            Type type = new TypeToken<Map<String, Object>>() {
            }.getType();
            Map<String, Object> map = gson().fromJson(json.getAsJsonObject(), type);
            return new Payload.Builder(map)
                    .build();
        }
    }

    public static class DocumentSerializer implements JsonSerializer<Document> {

        @Override
        public JsonElement serialize(Document src, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject document = new JsonObject();

            document.addProperty(PropertyName.KEY_DOCUMENT_CONTEXT, PropertyName.VALUE_DOCUMENT_CONTEXT);
            document.addProperty(PropertyName.KEY_DOCUMENT_ID, src.getId());
            document.addProperty(PropertyName.KEY_DOCUMENT_CREATED, src.getCreated());

            List<PublicKeyProperty> publicKeys = new ArrayList<>(src.getPublicKeyProperty().values());
            JsonParser parser = new JsonParser();
            JsonArray publicKey = parser.parse(gson().toJson(publicKeys)).getAsJsonArray();
            document.add(PropertyName.KEY_DOCUMENT_PUBLICKEY, publicKey);

            JsonArray authentication = parser.parse(gson().toJson(src.getAuthentication())).getAsJsonArray();
            document.add(PropertyName.KEY_DOCUMENT_AUTHENTICATION, authentication);

            if (src.getUpdated() != 0) {
                document.addProperty(PropertyName.KEY_DOCUMENT_UPDATED, src.getUpdated());
            }

            return document;
        }
    }

    public static class DocumentDeserializer implements JsonDeserializer<Document> {

        @Override
        public Document deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            JsonObject document = json.getAsJsonObject();

            JsonArray publicKeyArray = document.get(PropertyName.KEY_DOCUMENT_PUBLICKEY).getAsJsonArray();
            Type publicKeyType = new TypeToken<ArrayList<PublicKeyProperty>>() {
            }.getType();
            List<PublicKeyProperty> publicKeys = gson().fromJson(publicKeyArray, publicKeyType);
            Map<String, PublicKeyProperty> publicKeymap = new HashMap<>();
            for (PublicKeyProperty it : publicKeys) {
                publicKeymap.put(it.getId(), it);
            }

            JsonArray authenticationArray = document.get(PropertyName.KEY_DOCUMENT_AUTHENTICATION).getAsJsonArray();
            Type authenticationType = new TypeToken<ArrayList<AuthenticationProperty>>() {
            }.getType();
            List<AuthenticationProperty> authentications = gson().fromJson(authenticationArray, authenticationType);

            Document.Builder builder = new Document.Builder()
                    .id(document.get(PropertyName.KEY_DOCUMENT_ID).getAsString())
                    .created(document.get(PropertyName.KEY_DOCUMENT_CREATED).getAsLong())
                    .publicKey(publicKeymap)
                    .authentication(authentications);

            if (document.has(PropertyName.KEY_DOCUMENT_UPDATED)) {
                builder.updated(document.get(PropertyName.KEY_DOCUMENT_UPDATED).getAsLong());
            }

            return builder.build();
        }
    }

    public static class PublicKeySerializer implements JsonSerializer<PublicKeyProperty> {

        @Override
        public JsonElement serialize(PublicKeyProperty src, Type typeOfSrc, JsonSerializationContext context) {

            JsonObject object = new JsonObject();
            object.addProperty(PropertyName.KEY_DOCUMENT_PUBLICKEY_ID, src.getId());

            JsonParser parser = new JsonParser();
            JsonArray publicKeyType = parser.parse(gson().toJson(src.getType())).getAsJsonArray();
            object.add(PropertyName.KEY_DOCUMENT_PUBLICKEY_TYPE, publicKeyType);

            PublicKey publicKey = src.getPublicKey();
            Algorithm algorithm = AlgorithmProvider.create(src.getAlgorithmType());

            object.addProperty(src.getEncodeType().getValue(),
                    src.getEncodeType().encode(algorithm.publicKeyToByte(publicKey)));

            if (src.getCreated() > 0) {
                object.addProperty(PropertyName.KEY_DOCUMENT_PUBLICKEY_CREATED, src.getCreated());
            }

            if (src.isRevoked()) {
                object.addProperty(PropertyName.KEY_DOCUMENT_PUBLICKEY_REVOKED, src.getRevoked());
            }

            return object;
        }
    }


    public static class PublicKeyDeserializer implements JsonDeserializer<PublicKeyProperty> {

        @Override
        public PublicKeyProperty deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            JsonObject object = json.getAsJsonObject();

            String strPubKey = null;
            EncodeType encodeType = null;
            if (object.has(PropertyName.KEY_DOCUMENT_PUBLICKEY_HEX)) {
                strPubKey = object.get(PropertyName.KEY_DOCUMENT_PUBLICKEY_HEX).getAsString();
                encodeType = EncodeType.HEX;
            } else if (object.has(PropertyName.KEY_DOCUMENT_PUBLICKEY_BASE64)) {
                strPubKey = object.get(PropertyName.KEY_DOCUMENT_PUBLICKEY_BASE64).getAsString();
                encodeType = EncodeType.BASE64;
            } else {
                throw new ResolveException("Could not find public key");
            }

            Type listType = new TypeToken<List<String>>() {
            }.getType();

            if (!object.has(PropertyName.KEY_DOCUMENT_PUBLICKEY_TYPE)) {
                throw new ResolveException("Could not find type");
            }

            if (!object.has(PropertyName.KEY_DOCUMENT_PUBLICKEY_ID)) {
                throw new ResolveException("Could not find id");
            }

            try {
                List<String> types = new Gson().fromJson(object.get(PropertyName.KEY_DOCUMENT_PUBLICKEY_TYPE), listType);
                Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.fromIdentifier(types.get(0)));
                PublicKey publicKey = algorithm.byteToPublicKey(encodeType.decode(strPubKey));

                PublicKeyProperty.Builder builder = new PublicKeyProperty.Builder()
                        .id(object.get(PropertyName.KEY_DOCUMENT_PUBLICKEY_ID).getAsString())
                        .type(types)
                        .publicKey(publicKey)
                        .encodeType(encodeType);

                if (object.has(PropertyName.KEY_DOCUMENT_PUBLICKEY_CREATED)) {
                    builder.created(object.get(PropertyName.KEY_DOCUMENT_PUBLICKEY_CREATED).getAsLong());
                }

                if (object.has(PropertyName.KEY_DOCUMENT_PUBLICKEY_REVOKED)) {
                    builder.revoked(object.get(PropertyName.KEY_DOCUMENT_PUBLICKEY_REVOKED).getAsLong());
                }
                return builder.build();

            } catch (KeyPairException e) {
                throw new ResolveException("Could not load public key! key:" + strPubKey);
            }

        }
    }


    public static class AuthenticationDeserializer implements JsonDeserializer<AuthenticationProperty> {
        @Override
        public AuthenticationProperty deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            JsonObject object = json.getAsJsonObject();
            AuthenticationProperty.Builder builder = new AuthenticationProperty.Builder();
            if (object.has(PropertyName.KEY_DOCUMENT_AUTHENTICATION_TYPE)) {
                builder.type(object.get(PropertyName.KEY_DOCUMENT_AUTHENTICATION_TYPE).getAsString());
            }
            builder.publicKey(object.get(PropertyName.KEY_DOCUMENT_AUTHENTICATION_PUBLICKEY).getAsString());
            return builder.build();
        }
    }
}
