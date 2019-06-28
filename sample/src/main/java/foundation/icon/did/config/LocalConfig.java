package foundation.icon.did.config;

import foundation.icon.icx.data.Address;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.math.BigInteger;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
final public class LocalConfig implements SampleConfig {
    private final String nodeUrl = "http://localhost:9000/api/v3";
    private BigInteger networkId = BigInteger.valueOf(3);

    @Override
    public String getNodeUrl() {
        return nodeUrl;
    }

    @Override
    public BigInteger getNetworkId() {
        return networkId;
    }

    @Override
    public Address getScoreAddress() {
        return new Address("cx26484cf9cb42b6eebbf537fbfe6b7df3f86c5079");
    }

}
