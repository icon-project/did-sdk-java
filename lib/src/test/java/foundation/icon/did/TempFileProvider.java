package foundation.icon.did;

import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.nio.file.Files;



/**
 * Base class for tests wishing to use temporary file locations.
 */
public class TempFileProvider {
    private File tempDir;
    protected String tempDirPath;

    @BeforeEach
    public void setUp() throws Exception {
        tempDir = Files.createTempDirectory(
                TempFileProvider.class.getSimpleName()).toFile();
        tempDirPath = tempDir.getPath();
    }

    public void tearDown() throws Exception {
        for (File file:tempDir.listFiles()) {
            file.delete();
        }
        tempDir.delete();
    }
}
