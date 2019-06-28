package foundation.icon.did.jwt;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Header {
    // header
    private String alg;
    private String kid;

    private Header(Builder builder) {
        alg = builder.alg;
        kid = builder.kid;
    }

    public String getAlg() {
        return alg;
    }

    public String getKid() {
        return kid;
    }



    @Override
    public String toString() {
        return "Header{" +
                "alg='" + alg + '\'' +
                ", kid='" + kid + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Header)) return false;
        Header header = (Header) o;
        return Objects.equals(alg, header.alg) &&
                Objects.equals(kid, header.kid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(alg, kid);
    }

    public static final class Builder {
        private String alg;
        private String kid;

        public Builder() {
        }

        public Builder alg(String val) {
            alg = val;
            return this;
        }

        public Builder kid(String val) {
            kid = val;
            return this;
        }

        public Header build() {
            return new Header(this);
        }
    }
}
