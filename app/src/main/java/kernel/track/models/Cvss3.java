package kernel.track.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class Cvss3 implements Cvss {
    @JsonProperty("Attack Complexity")
    private String attackComplexity;

    @JsonProperty("Attack Vector")
    private String attackVector;

    @JsonProperty("Availability")
    private String availability;

    @JsonProperty("Confidentiality")
    private String confidentiality;

    @JsonProperty("Integrity")
    private String integrity;

    @JsonProperty("Privileges Required")
    private String privilegesRequired;

    @JsonProperty("Scope")
    private String scope;

    @JsonProperty("User Interaction")
    private String userInteraction;

    private double score;

    public boolean isNone() {
        return score == 0.0;
    }

    @Override
    public boolean isLow() {
        return score > 0.0 && score < 4.0;
    }

    @Override
    public boolean isMedium() {
        return score >= 4.0 && score < 7.0;
    }

    @Override
    public boolean isHigh() {
        return score >= 7.0 && score < 9.0;
    }

    public boolean isCritical() {
        return score >= 9.0 && score <= 10.0;
    }

}
