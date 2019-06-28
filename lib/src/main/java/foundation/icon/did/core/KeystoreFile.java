package foundation.icon.did.core;

/**
 * Original Code
 * https://github.com/web3j/web3j/blob/master/crypto/src/main/java/org/web3j/crypto/WalletFile.java
 * Icon wallet file.
 */
@SuppressWarnings("WeakerAccess")
public class KeystoreFile {
    private String did;
    private String keyId;
    private String type;
    private Crypto crypto;
    private String id;
    private int version;

    public KeystoreFile() {
    }

    public String getDid() {
        return did;
    }

    public void setDid(String did) {
        this.did = did;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getKid() {
        return getDid() + "#" + getKeyId();
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof KeystoreFile)) {
            return false;
        }

        KeystoreFile that = (KeystoreFile) o;
        if (getKid() != null
                ? !getKid().equals(that.getKid())
                : that.getKid() != null) {
            return false;
        }
        if (getCrypto() != null
                ? !getCrypto().equals(that.getCrypto())
                : that.getCrypto() != null) {
            return false;
        }
        if (getId() != null
                ? !getId().equals(that.getId())
                : that.getId() != null) {
            return false;
        }
        return version == that.version;
    }

    @Override
    public int hashCode() {
        int result = getKid() != null ? getKid().hashCode() : 0;
        result = 31 * result + (getCrypto() != null ? getCrypto().hashCode() : 0);
        result = 31 * result + (getId() != null ? getId().hashCode() : 0);
        result = 31 * result + version;
        return result;
    }

    public static class Crypto {
        private String cipher;
        private String ciphertext;
        private CipherParams cipherparams;

        private String kdf;
        private ScryptKdfParams kdfparams;

        private String mac;

        public Crypto() {
        }

        public String getCipher() {
            return cipher;
        }

        public void setCipher(String cipher) {
            this.cipher = cipher;
        }

        public String getCiphertext() {
            return ciphertext;
        }

        public void setCiphertext(String ciphertext) {
            this.ciphertext = ciphertext;
        }

        public CipherParams getCipherparams() {
            return cipherparams;
        }

        public void setCipherparams(CipherParams cipherparams) {
            this.cipherparams = cipherparams;
        }

        public String getKdf() {
            return kdf;
        }

        public void setKdf(String kdf) {
            this.kdf = kdf;
        }

        public ScryptKdfParams getKdfparams() {
            return kdfparams;
        }

        public void setKdfparams(ScryptKdfParams kdfparams) {
            this.kdfparams = kdfparams;
        }

        public String getMac() {
            return mac;
        }

        public void setMac(String mac) {
            this.mac = mac;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Crypto)) {
                return false;
            }

            Crypto that = (Crypto) o;

            if (getCipher() != null
                    ? !getCipher().equals(that.getCipher())
                    : that.getCipher() != null) {
                return false;
            }
            if (getCiphertext() != null
                    ? !getCiphertext().equals(that.getCiphertext())
                    : that.getCiphertext() != null) {
                return false;
            }
            if (getCipherparams() != null
                    ? !getCipherparams().equals(that.getCipherparams())
                    : that.getCipherparams() != null) {
                return false;
            }
            if (getKdf() != null
                    ? !getKdf().equals(that.getKdf())
                    : that.getKdf() != null) {
                return false;
            }
            if (getKdfparams() != null
                    ? !getKdfparams().equals(that.getKdfparams())
                    : that.getKdfparams() != null) {
                return false;
            }
            return getMac() != null
                    ? getMac().equals(that.getMac()) : that.getMac() == null;
        }

        @Override
        public int hashCode() {
            int result = getCipher() != null ? getCipher().hashCode() : 0;
            result = 31 * result + (getCiphertext() != null ? getCiphertext().hashCode() : 0);
            result = 31 * result + (getCipherparams() != null ? getCipherparams().hashCode() : 0);
            result = 31 * result + (getKdf() != null ? getKdf().hashCode() : 0);
            result = 31 * result + (getKdfparams() != null ? getKdfparams().hashCode() : 0);
            result = 31 * result + (getMac() != null ? getMac().hashCode() : 0);
            return result;
        }

    }

    public static class CipherParams {
        private String iv;

        public CipherParams() {
        }

        public String getIv() {
            return iv;
        }

        public void setIv(String iv) {
            this.iv = iv;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof CipherParams)) {
                return false;
            }

            CipherParams that = (CipherParams) o;

            return getIv() != null
                    ? getIv().equals(that.getIv()) : that.getIv() == null;
        }

        @Override
        public int hashCode() {
            int result = getIv() != null ? getIv().hashCode() : 0;
            return result;
        }

    }

    public static class ScryptKdfParams {
        private int dklen;
        private int n;
        private int p;
        private int r;
        private String salt;

        public ScryptKdfParams() {
        }

        public int getDklen() {
            return dklen;
        }

        public void setDklen(int dklen) {
            this.dklen = dklen;
        }

        public int getN() {
            return n;
        }

        public void setN(int n) {
            this.n = n;
        }

        public int getP() {
            return p;
        }

        public void setP(int p) {
            this.p = p;
        }

        public int getR() {
            return r;
        }

        public void setR(int r) {
            this.r = r;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof ScryptKdfParams)) {
                return false;
            }

            ScryptKdfParams that = (ScryptKdfParams) o;

            if (dklen != that.dklen) {
                return false;
            }
            if (n != that.n) {
                return false;
            }
            if (p != that.p) {
                return false;
            }
            if (r != that.r) {
                return false;
            }
            return getSalt() != null
                    ? getSalt().equals(that.getSalt()) : that.getSalt() == null;
        }

        @Override
        public int hashCode() {
            int result = dklen;
            result = 31 * result + n;
            result = 31 * result + p;
            result = 31 * result + r;
            result = 31 * result + (getSalt() != null ? getSalt().hashCode() : 0);
            return result;
        }
    }

}
