package foundation.icon.did.jwt;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.*;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Payload {

    public static final String TYPE = "type";
    public static final String ISSUER = "iss";
    public static final String SUBJECT = "sub";
    public static final String AUDIENCE = "aud";
    public static final String ISSUED_AT = "iat";
    public static final String EXPIRATION = "exp";
    public static final String JTI = "jti";
    public static final String CLAIM = "claim";
    public static final String CREDENTIAL = "credential";
    public static final String NONCE = "nonce";
    public static final String VERSION = "version";

    private Map<String, Object> map;
    private List<String> timeClaimKeys;

    Payload() {
        map = new TreeMap<>();
        timeClaimKeys = new ArrayList<>();
        timeClaimKeys.add(EXPIRATION);
        timeClaimKeys.add(ISSUED_AT);
    }

    Payload(Map<String, Object> map) {
        this();
        putAll(map);
    }

    public String getType() {
        return get(TYPE, String.class);
    }

    public List<String> getTypes() {
        return get(TYPE, List.class);
    }

    public String getIss() {
        return get(ISSUER, String.class);
    }

    public String getSub() {
        return get(SUBJECT, String.class);
    }

    public String getAud() { return get(AUDIENCE, String.class); }

    public Date getIat() {
        return get(ISSUED_AT, Date.class);
    }

    public Date getExp() {
        return get(EXPIRATION, Date.class);
    }

    public Map<String, Object> getClaim() {
        return get(CLAIM, Map.class);
    }

    public List<String> getCredential() {
        return get(CREDENTIAL, List.class);
    }

    public String getNonce() {
        return get(NONCE, String.class);
    }

    public Map<String, Object> getMap() {
        return map;
    }

    public String getVersion() { return get(VERSION, String.class); }

    public Object put(String name, Object value) {
        if (value == null) {
            return map.remove(name);
        } else {
            if (isTimeClaim(name)) {
                value = toTimeStamp(value);
            }
            return map.put(name, value);
        }
    }

    public void putAll(Map<? extends String, ?> m) {
        if (m == null) {
            return;
        }
        for (String s : m.keySet()) {
            put(s, m.get(s));
        }
    }

    public Object get(Object o) {
        return map.get(o);
    }

    public <T> T get(String key, Class<T> type) {
        Object value = get(key);
        if (value == null) {
            return null;
        }

        if (Date.class.equals(type) && isTimeClaim(key)) {
            long seconds = (long) toTimeStamp(value);
            value = new Date(seconds * 1000);
        }

        return type.cast(value);
    }

    public void addTimeClaimKey(String key) {
        timeClaimKeys.add(key);
    }

    public void addTimeClaimKeys(List<String> keys) {
        timeClaimKeys.addAll(keys);
    }

    private boolean isTimeClaim(String key) {
        return timeClaimKeys.contains(key);
    }

    protected static Object toTimeStamp(Object v) {
        if (v == null) {
            return null;
        } else if (v instanceof Number) {
            v = ((Number) v).longValue();
        } else if (v instanceof String) {
            try {
                v = Long.parseLong((String) v);
            } catch (NumberFormatException ignored) {
            }
        }
        return v;
    }

    public static final class Builder {

        // payload
        private Map<String, Object> payload;
        private List<String> timeClaimKeys;

        public Builder() {
            payload = new HashMap<>();
            timeClaimKeys = new ArrayList<>();
        }

        public Builder(Map<String, Object> payload) {
            this.payload = payload;
            timeClaimKeys = new ArrayList<>();
        }

        public Builder type(List<String> types) {
            this.payload.put(Payload.TYPE, types);
            return this;
        }

        public Builder type(String type) {
            this.payload.put(Payload.TYPE, type);
            return this;
        }

        public Builder iss(String iss) {
            this.payload.put(Payload.ISSUER, iss);
            return this;
        }

        public Builder sub(String sub) {
            this.payload.put(Payload.SUBJECT, sub);
            return this;
        }

        public Builder aud(String aud) {
            this.payload.put(Payload.AUDIENCE, aud);
            return this;
        }

        public Builder iat(Date iat) {
            this.payload.put(Payload.ISSUED_AT, dateToSeconds(iat));
            return this;
        }

        public Builder exp(Date exp) {
            this.payload.put(Payload.EXPIRATION, dateToSeconds(exp));
            return this;
        }

        public Builder claim(Map<String, Object> claim) {
            this.payload.put(Payload.CLAIM, claim);
            return this;
        }

        public Builder credential(List<String> credential) {
            this.payload.put(Payload.CREDENTIAL, credential);
            return this;
        }

        public Builder nonce(String nonce) {
            this.payload.put(Payload.NONCE, nonce);
            return this;
        }

        public Builder jti(String jti) {
            this.payload.put(Payload.JTI, jti);
            return this;
        }

        public Builder version(String version) {
            this.payload.put(Payload.VERSION, version);
            return this;
        }

        public Builder put(String name, Object value) {
            if (value == null) {
                this.payload.remove(name);
            } else {
                this.payload.put(name, value);
            }
            return this;
        }

        public Builder addTimeClaimKey(String key) {
            this.timeClaimKeys.add(key);
            return this;
        }

        private long dateToSeconds(Date d) {
            if (d == null) throw new IllegalArgumentException("Date must not be null");
            return d.getTime() / 1000;
        }

        public Payload build() {
            Payload payload = new Payload(this.payload);
            if (!this.timeClaimKeys.isEmpty()) payload.addTimeClaimKeys(this.timeClaimKeys);
            return payload;
        }
    }

    @Override
    public String toString() {
        return "Payload{" +
                "map=" + map +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Payload)) return false;
        Payload payload = (Payload) o;
        return Objects.equals(map, payload.map);
    }

    @Override
    public int hashCode() {
        return Objects.hash(map);
    }
}
