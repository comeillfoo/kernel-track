package kernel.track.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class Cvss3 {
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

    private String score;
}
