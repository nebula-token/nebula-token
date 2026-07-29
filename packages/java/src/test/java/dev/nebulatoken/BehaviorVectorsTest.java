package dev.nebulatoken;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The normative behavioral suite -- spec/behavior-vectors.json ([N-47], [N-49]).
 *
 * <p>Every scenario here is a published vector, not a hand-written case, so this
 * suite cannot silently drift from the other nine implementations. Anything that
 * cannot be expressed as a portable vector lives in {@link EngineTest}.
 */
class BehaviorVectorsTest {

    private static final JsonNode VECTORS = BehaviorRunner.load();

    @Test
    void everyApplicableScenarioPasses() {
        BehaviorRunner.RunOutcome outcome = BehaviorRunner.run(VECTORS);

        // [N-48]: a runner that silently iterated nothing must not report success.
        int published = VECTORS.get("counts").get("scenarios").asInt();
        assertEquals(published, outcome.executed().size() + outcome.skipped().size(),
                "every published scenario must be either executed or explicitly skipped");
        assertTrue(outcome.executed().size() >= VECTORS.get("counts").get("unconditional").asInt(),
                "every unconditional scenario must be executed");

        // Java strings are UTF-16 and admit a lone surrogate, so the only
        // published condition holds here and nothing should be skipped.
        assertEquals(List.of(), outcome.skipped(),
                "skipped scenarios (reported by id and condition)");
    }

    /** One test per scenario, each in its own store, so a failure names itself. */
    @TestFactory
    List<DynamicTest> scenarios() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode scenario : VECTORS.get("scenarios")) {
            String id = scenario.get("id").asText();
            String condition = scenario.has("condition") ? scenario.get("condition").asText() : null;
            if (condition != null && !BehaviorRunner.SATISFIED_CONDITIONS.contains(condition)) {
                tests.add(DynamicTest.dynamicTest(id + " [skipped: " + condition + "]", () -> {}));
                continue;
            }
            tests.add(DynamicTest.dynamicTest(id + " -- " + scenario.get("title").asText(),
                    () -> BehaviorRunner.runScenario(VECTORS, scenario)));
        }
        assertEquals(VECTORS.get("counts").get("scenarios").asInt(), tests.size(),
                "every published scenario must produce a test ([N-48])");
        return tests;
    }
}
