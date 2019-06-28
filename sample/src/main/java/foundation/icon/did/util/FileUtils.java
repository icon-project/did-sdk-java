package foundation.icon.did.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.*;

public class FileUtils {

    public static void writeClaim(String fileName, String key, String value) {
        JsonObject object = new JsonObject();
        object.addProperty(key, value);

        try (Writer writer = new FileWriter(fileName)) {
            Gson gson = new GsonBuilder().create();
            gson.toJson(object, writer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String loadClaim(String fileName, String key) throws FileNotFoundException {
        InputStreamReader reader = new InputStreamReader(new FileInputStream(fileName));
        JsonParser parser = new JsonParser();
        JsonObject object = parser.parse(reader).getAsJsonObject();
        return object.get(key).getAsString();
    }

}
