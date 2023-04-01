package kernel.track;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.IntStream;

import org.junit.Test;

import kernel.track.models.Cvss;
import kernel.track.models.Cvss2;
import kernel.track.models.Cvss3;

public class CvssTest {

    private void testSeverity(int start, int finish, Function<Cvss, Boolean> action) {
        final List<Cvss> CUTS = Arrays.asList(new Cvss2(), new Cvss3());
        final double begin = start / 10.0;
        final double end = finish / 10.0;
        IntStream.rangeClosed(0, 100)
            .mapToDouble((number)->(number / 10.0))
            .forEach((score)->{
                CUTS.forEach((cut)->{
                    cut.setScore(score);
                    if (score >= begin && score < end)
                        assertTrue(action.apply(cut));
                    else
                        assertFalse(action.apply(cut));
                });
            });
    }

    @Test
    public void testIsLow() {
        testSeverity(1, 40, Cvss::isLow);
    }

    @Test
    public void testIsMedium() {
        testSeverity(40, 70, Cvss::isMedium);
    }

    @Test
    public void testIsHigh() {
        testSeverity(70, 90, Cvss::isHigh);
    }

    @Test
    public void testIsCritical() {
        final Cvss3 classUnderTests = new Cvss3();
        IntStream.rangeClosed(0, 100)
            .mapToDouble((number)->(number / 10.0))
            .forEach((score)->{
                classUnderTests.setScore(score);
                if (score >= 9.0 && score <= 10.0)
                    assertTrue(classUnderTests.isCritical());
                else
                    assertFalse(classUnderTests.isCritical());
            });
    }

    @Test
    public void testIsNone() {
        final Cvss3 classUnderTests = new Cvss3();
        IntStream.rangeClosed(0, 100)
            .mapToDouble((number)->(number / 10.0))
            .forEach((score)->{
                classUnderTests.setScore(score);
                if (score == 0.0)
                    assertTrue(classUnderTests.isNone());
                else
                    assertFalse(classUnderTests.isNone());
            });
    }
}
