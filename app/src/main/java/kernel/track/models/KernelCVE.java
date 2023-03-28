package kernel.track.models;

import java.util.Map;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class KernelCVE {

    private String id;

    @JsonProperty("affected_versions")
    private String affectedVersions;

    @JsonProperty("alt_msg")
    private String alternativeMessage;

    private boolean backport;
    private String breaks;

    @JsonProperty("cmt_msg")
    private String commitMessage;

    private Cvss2 cvss2;

    private Cvss3 cvss3;

    private String cwe;

    private String fixes;

    @JsonProperty("last_affected_version")
    private String lastAffectedVersion;

    @JsonProperty("last_modified")
    private String lastModified;

    @JsonProperty("new")
    private String isNew;

    private String name;

    @JsonProperty("nvd_text")
    private String nvdText;

    @JsonProperty("ref_urls")
    private Map<String, String> referenceUrls;

    @JsonProperty("vendor_specific")
    private boolean vendorSpecific;

    private boolean rejected;

    public boolean isHighOrCritical() {
        if (cvss3 != null)
            return cvss3.isCritical() || cvss3.isHigh();
        if (cvss2 != null)
            return cvss2.isHigh();
        return true;
    }

    public double getCvssScore() {
        if (cvss3 != null)
            return cvss3.getScore();
        if (cvss2 != null)
            return cvss2.getScore();
        return 99.9;
    }
}
