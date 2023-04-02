package kernel.track.models;

import java.util.stream.Stream;


public class KernelVersion implements Comparable<KernelVersion> {

    public static int[] parseVersion(String version) {
        return Stream.of((version + ".0").split("\\."))
            .mapToInt(Integer::parseInt)
            .toArray();
    }

    public final int VERSION;
    public final int PATCHLEVEL;
    public final int SUBLEVEL;
    public final String FULL_VERSION;
    public final String STREAM_VERSION;

    public KernelVersion(String version) {
        if ("outstanding".equals(version)) {
            VERSION = Integer.MAX_VALUE;
            PATCHLEVEL = Integer.MAX_VALUE;
            SUBLEVEL = Integer.MAX_VALUE;
            FULL_VERSION = version;
            STREAM_VERSION = version;
            return;
        }
        int[] versions = KernelVersion.parseVersion(version);
        VERSION = versions[0];
        PATCHLEVEL = versions[1];
        SUBLEVEL = versions[2];
        FULL_VERSION = String.join(".",
            Stream.of(versions)
                .map(String::valueOf)
                .toArray(String[]::new));
        STREAM_VERSION = String.format("%d.%d", VERSION, PATCHLEVEL);
    }

    @Override
    public String toString() {
        return FULL_VERSION;
    }

    @Override
    public int compareTo(KernelVersion o) {
        if ("outstanding".equals(this.FULL_VERSION)) return 1;
        if ("outstanding".equals(o.FULL_VERSION)) return -1;
        return ((this.VERSION - o.VERSION) * 10
            + (this.PATCHLEVEL - o.PATCHLEVEL)) * 10
            + this.SUBLEVEL - o.SUBLEVEL;
    }
}
