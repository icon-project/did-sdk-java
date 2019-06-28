package foundation.icon.did.document;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public enum EncodeType implements Encoder {
    HEX("publicKeyHex") {
        public String encode(byte[] data) {
            return Hex.toHexString(data);
        }

        public byte[] decode(String data) {
            return Hex.decode(data);
        }
    },
    BASE64("publicKeyBase64") {
        public String encode(byte[] data) {
            return Base64.toBase64String(data);
        }

        public byte[] decode(String data) {
            return Base64.decode(data);
        }
    };

    private String name;

    EncodeType(String name) {
        this.name = name;
    }

    public String getValue() {
        return name;
    }

    public static EncodeType fromString(String type) {
        if (type != null) {
            for (EncodeType t : EncodeType.values()) {
                if (type.equalsIgnoreCase(t.getValue())) {
                    return t;
                }
            }
        }
        return null;
    }
}
