package kernel.track.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class Cvss2 implements Cvss {
    @JsonProperty("Access Complexity")
    private String accessComplexity;

    @JsonProperty("Access Vector")
    private String accessVector;

    @JsonProperty("Authentication")
    private String authentication;

    @JsonProperty("Availability Impact")
    private String availabilityImpact;

    @JsonProperty("Confidentiality Impact")
    private String confidentialityImpact;

    @JsonProperty("Integrity Impact")
    private String integrityImpact;

    private double score;

    @Override
    public boolean isLow() {
        return score >= 0.0 && score < 4.0;
    }

    @Override
    public boolean isMedium() {
        return score >= 4.0 && score < 7.0;
    }

    @Override
    public boolean isHigh() {
        return score >= 7.0 && score <= 10.0;
    }
}
