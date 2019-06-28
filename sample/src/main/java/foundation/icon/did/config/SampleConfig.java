package foundation.icon.did.config;

import foundation.icon.icx.IconService;
import foundation.icon.icx.data.Address;
import foundation.icon.icx.transport.http.HttpProvider;
import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

public interface SampleConfig {

    String OWNER_KEY_FILE_NAME = "owner.json";
    String ISSUER_KEY_FILE_NAME = "issuer.json";
    String CREDENTIAL_FILE_NAME = "credential.json";
    String PRESENTATION_FILE_NAME = "presentation.json";

    String TEST_PASSWORD = "P@ssw0rd";

    boolean DEBUG = false;

    String getNodeUrl();

    BigInteger getNetworkId();

    Address getScoreAddress();

    default IconService iconService() {
        return new IconService(createHttpProvider(getNodeUrl()));
    }

    default HttpProvider createHttpProvider(String url) {
        if (!DEBUG) {
            return new HttpProvider(url);
        } else {
            HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
            logging.setLevel(HttpLoggingInterceptor.Level.BODY);
            OkHttpClient httpClient = new OkHttpClient.Builder()
                    .addInterceptor(logging)
                    .readTimeout(100L, TimeUnit.SECONDS)
                    .build();
            return new HttpProvider(httpClient, url);
        }
    }

    static SampleConfig dev() {
        return new DevConfig();
    }

    static SampleConfig local() {
        return new LocalConfig();
    }
}
