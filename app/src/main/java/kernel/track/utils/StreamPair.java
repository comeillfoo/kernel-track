package kernel.track.utils;

import java.util.Set;

public class StreamPair {
    public final Set<String> FIXED;
    public final Set<String> UNFIXED;

    public StreamPair(Set<String> fixed, Set<String> unfixed) {
        FIXED = fixed;
        UNFIXED = unfixed;
    }
}
