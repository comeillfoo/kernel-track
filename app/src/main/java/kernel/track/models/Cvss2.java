package kernel.track.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class Cvss2 {
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

    private String score;
}
