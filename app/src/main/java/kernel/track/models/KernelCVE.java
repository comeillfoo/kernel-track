package kernel.track.models;

import java.util.Map;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class KernelCVE {

    @JsonProperty("affected_versions")
    private String affectedVersions;

    private boolean backport;
    private String breaks;

    @JsonProperty("cmt_msg")
    private String commitMessage;

    private Cvss2 cvss2;

    private Cvss3 cvss3;

    private String cwe;

    private String fixes;

    private String nvd_text;

    @JsonProperty("ref_urls")
    private Map<String, String> referenceUrls;
}
