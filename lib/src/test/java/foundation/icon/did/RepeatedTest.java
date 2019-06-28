package foundation.icon.did;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.KeyProvider;
import foundation.icon.did.document.Document;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.score.ScoreParameter;
import foundation.icon.icx.IconService;
import foundation.icon.icx.KeyWallet;
import foundation.icon.icx.data.Address;
import foundation.icon.icx.data.Bytes;
import org.junit.jupiter.api.Disabled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.stream.Collectors;

@Disabled
public class RepeatedTest {

    private static Logger logger = LoggerFactory.getLogger(RepeatedTest.class);

    private static int count = 0;

    public static void main(String[] args) throws InterruptedException, IOException {
        BigInteger networkId = new BigInteger("3");
        IconService iconService = IconServiceFactory.createLocal();
        Address scoreAddress = new Address("cx26484cf9cb42b6eebbf537fbfe6b7df3f86c5079");
        String keyId = "key";

        AlgorithmProvider.Type type = AlgorithmProvider.Type.ES256K;
        Algorithm algorithm = AlgorithmProvider.create(type);

        ThreadPoolExecutor executorService = (ThreadPoolExecutor) Executors.newFixedThreadPool(5);
        List<Document> documents = Collections.synchronizedList(new ArrayList<>());
        List<KeyWallet> wallets = loadMillionWalletJson(10);
        wallets.forEach(wallet -> {
            executorService.submit(() -> {
                try {
                    KeyProvider keyProvider = algorithm.generateKeyProvider(keyId);
                    String json = ScoreParameter.create(keyProvider, EncodeType.BASE64);
                    DidService didService = new DidService(iconService, networkId, scoreAddress);
                    Document doc = didService.create(wallet, json);
                    documents.add(doc);
                    System.out.println((count++) + " - " + doc.toJson());
                } catch (AlgorithmException | IOException e) {
                    e.printStackTrace();
                }
            });
        });

        while (executorService.getActiveCount() > 0) {
            logger.debug("current active thread = " + executorService.getActiveCount());
            Thread.sleep(1000);
        }

        executorService.shutdown();

        logger.debug("count = " + count);
        logger.debug("expected count = " + wallets.size());
        logger.debug("document count = " + documents.size());
    }

    static List<KeyWallet> loadMillionWalletJson(int count) throws IOException {
        String path = Objects.requireNonNull(RepeatedTest.class.getClassLoader().getResource("investors.json")).getPath();
//        Path path = Paths.get(System.getProperty("user.dir"), "icon-sdk/keystore", "investors.json");
        File jsonFile = new File(path);

        ObjectMapper mapper = new ObjectMapper();
        JavaType type = mapper.getTypeFactory().
                constructCollectionType(List.class, String.class);
        List<String> privateKeys = mapper.readValue(jsonFile, type);
        return privateKeys.stream()
                .limit(count)
                .map(privateKey -> {
                    System.out.print(".");
                    return KeyWallet.load(new Bytes(privateKey));
                })
                .collect(Collectors.toList());
    }
}
