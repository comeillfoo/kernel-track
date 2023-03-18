package kernel.track.utils;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class StreamPair {
    public final Set<String> FIXED;
    public final Set<String> UNFIXED;

    public StreamPair(Set<String> fixed, Set<String> unfixed) {
        FIXED = fixed;
        UNFIXED = unfixed;
    }

    private static int parseSublevel(String version) {
        return Integer.parseInt((version + ".0").split("\\.")[2]);
    }

    public static StreamPair of(JsonNode streams, String version) {
        final String[] versions = (version + ".0").split("\\.");
        final int sublevel = parseSublevel(version);
        String streamVersion = String.join(".", versions[0], versions[1]);
        Map<String, Map<String, Map<String, String>>> substreams =
            new ObjectMapper()
                .convertValue(streams.get(streamVersion), new TypeReference<Map<String, Map<String, Map<String, String>>>>() {});

        Set<String> fixed = new HashSet<>();
        Set<String> unfixed = new HashSet<>();
        substreams.entrySet().forEach((e) -> {
            String substream = e.getKey();
            e.getValue().keySet().forEach((cve) -> {
                if ("outstanding".equals(substream) || parseSublevel(substream) > sublevel)
                    unfixed.add(cve);
                else
                    fixed.add(cve);
            });
        });
        return new StreamPair(fixed, unfixed);
    }
}
