package kernel.track.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
public class Cvss2 extends Cvss {
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

    @Override
    public boolean isLow() {
        return getScore() >= 0.0 && getScore() < 4.0;
    }

    @Override
    public boolean isMedium() {
        return getScore() >= 4.0 && getScore() < 7.0;
    }

    @Override
    public boolean isHigh() {
        return getScore() >= 7.0 && getScore() <= 10.0;
    }

    public Cvss2(String value) {
        setScore(Double.parseDouble(value));
    }
}
