package foundation.icon.did.config;

import foundation.icon.icx.data.Address;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.math.BigInteger;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
final public class DevConfig implements SampleConfig {
    private String nodeUrl = "https://test-ctz.solidwallet.io/api/v3";
    private BigInteger networkId = BigInteger.valueOf(2);

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
        return new Address("cx9a96c0dcf0567635309809d391908c32fcca5310");
    }

}
