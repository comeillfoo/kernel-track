package kernel.track.models;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;


public class KernelVersion implements Comparable<KernelVersion> {

    public static int[] parseVersion(String version) {
        return Stream.of((version + ".0").split("\\."))
            .mapToInt(Integer::parseInt)
            .toArray();
    }

    private static final Pattern VERSION_PAT = Pattern.compile("VERSION\\s*=\\s*([0-9]+)");
    private static final Pattern PATCHLEVEL_PAT = Pattern.compile("PATCHLEVEL\\s*=\\s*([0-9]+)");
    private static final Pattern SUBLEVEL_PAT = Pattern.compile("SUBLEVEL\\s*=\\s*([0-9]+)");

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
        STREAM_VERSION = String.format("%d.%d", VERSION, PATCHLEVEL);
        FULL_VERSION = String.format("%s.%d", STREAM_VERSION, SUBLEVEL);
    }

    public static String parseMakefile(List<String> makefile) throws ParseException {
        return makefile.stream()
            .filter((line)->line.matches(VERSION_PAT.pattern())
                || line.matches(PATCHLEVEL_PAT.pattern())
                || line.matches(SUBLEVEL_PAT.pattern()))
            .map((line)-> {
                Matcher mVersion = VERSION_PAT.matcher(line);
                if (mVersion.matches()) return mVersion.group(1);
                Matcher mPatchlevel = PATCHLEVEL_PAT.matcher(line);
                if (mPatchlevel.matches()) return mPatchlevel.group(1);
                Matcher mSublevel = SUBLEVEL_PAT.matcher(line);
                if (mSublevel.matches()) return mSublevel.group(1);
                return "0";
            })
            .reduce((acc, element) -> acc.concat(".").concat(element))
            .orElseThrow(() -> new ParseException("malformed Makefile provided", 0));
    }

    public KernelVersion(Path kernel) throws IOException, ParseException {
        this(parseMakefile(Files.readAllLines(kernel.resolve("Makefile"))));
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
