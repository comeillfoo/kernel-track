package kernel.track.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
public class Cvss3 extends Cvss {
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

    public boolean isNone() {
        return getScore() == 0.0;
    }

    public boolean isCritical() {
        return getScore() >= 9.0 && getScore() <= 10.0;
    }

    public Cvss3(String value) {
        setScore(Double.parseDouble(value));
    }
}
