package foundation.icon.did.document;

public interface Encoder {
    String encode(byte[] data);
    byte[] decode(String data);
}
