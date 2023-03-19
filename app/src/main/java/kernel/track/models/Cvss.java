package kernel.track.models;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class Cvss {
    private String raw;

    private double score;

    public abstract boolean isLow();
    public abstract boolean isMedium();
    public abstract boolean isHigh();
}
