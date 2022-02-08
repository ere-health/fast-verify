package health.ere.verifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

public class SlowVerifierTest {

    @Test
    public void testVerifyAll() throws IOException {
        try (Stream<Path> paths = Files.walk(Paths.get("src/test/resources/signed-data/"))) {
            List<InputStream> is = paths
                .filter(Files::isRegularFile)
                .parallel()
                .map(p -> {
                    try {
                        return Files.readAllBytes(p);
                    } catch (IOException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .map(b -> new ByteArrayInputStream(b))
                .collect(Collectors.toList());

            Instant starts = Instant.now();
            
            assertEquals(is.stream().parallel().map(b -> SlowVerifier.verify(b)).filter(b -> !b).count(), 0l);

            Instant ends = Instant.now();
            System.out.println(Duration.between(starts, ends));
        }
    }

    @Test
    public void testVerify() {
        assertTrue(SlowVerifier.verify(getClass().getResourceAsStream("/signed-data/HEK_Beispiel_frei_1-null-17.p7b")));
    }

    @Test
    public void testNotVerify() {
        assertThrows(RuntimeException.class, () -> {
            SlowVerifier.verify(getClass().getResourceAsStream("/invalid-signed-data/HEK_Beispiel_frei_1-null-17.p7b"));
        });
    }
}
