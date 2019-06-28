package foundation.icon.did;

import foundation.icon.icx.IconService;
import foundation.icon.icx.transport.http.HttpProvider;
import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;

import java.util.concurrent.TimeUnit;

/**
 * Test 용으로 사용
 */
public class IconServiceFactory {

    private static boolean DEBUG = false;
    private static String LOCAL_URL = "http://127.0.0.1:9000/api/v3";
    private static String DEV_URL = "https://test-ctz.solidwallet.io/api/v3";

    private IconServiceFactory() {
    }

    public static IconService createLocal() {
        return create(LOCAL_URL);
    }

    public static IconService createDev() {
        return create(DEV_URL);
    }

    public static IconService create(String url) {
        return new IconService(createHttpProvider(url, DEBUG));
    }

    private static HttpProvider createHttpProvider(String url, boolean debug) {
        if (!debug) {
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
}
