package dev.nebulatoken;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Locates and loads the shared conformance artifacts in {@code spec/}.
 *
 * <p>The files are found by walking up from this class's own compiled location
 * to the repository root, never by a hardcoded path and never by a copy vendored
 * into this package: a stale copy is exactly how ten implementations start
 * disagreeing about what conformance means ([N-47], [N-49]).
 */
final class SpecVectors {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SpecVectors() {}

    static JsonNode load(String fileName) {
        Path file = specDir().resolve(fileName);
        try {
            return MAPPER.readTree(file.toFile());
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + file, e);
        }
    }

    private static Path specDir() {
        Path start = startingPoint();
        for (Path dir = start; dir != null; dir = dir.getParent()) {
            Path spec = dir.resolve("spec");
            if (Files.isRegularFile(spec.resolve("test-vectors.json"))) return spec;
        }
        throw new IllegalStateException("no spec/ directory found walking up from " + start);
    }

    /** target/test-classes when run by Maven; the working directory otherwise. */
    private static Path startingPoint() {
        try {
            return Path.of(SpecVectors.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
        } catch (Exception e) {
            return Path.of("").toAbsolutePath();
        }
    }
}
