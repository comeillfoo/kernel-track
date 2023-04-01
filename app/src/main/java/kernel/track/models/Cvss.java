package kernel.track.models;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class Cvss {
    private String raw;

    private double score;

    public boolean isLow() {
        return getScore() > 0.0 && getScore() < 4.0;
    }

    public boolean isMedium() {
        return getScore() >= 4.0 && getScore() < 7.0;
    }

    public boolean isHigh() {
        return getScore() >= 7.0 && getScore() < 9.0;
    }
}
