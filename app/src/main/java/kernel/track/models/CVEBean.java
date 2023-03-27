package kernel.track.models;

import java.util.List;

import kernel.track.mitigators.DebianMitigator;
import kernel.track.mitigators.RedHatMitigator;
import kernel.track.mitigators.UbuntuMitigator;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
public class CVEBean {
    private String date;
    private String cveid;
    private String source;
    private double cvssScore;
    private String status;
    private String patch;
    private String debianMitigation;
    private String ubuntuMitigation;
    private String redHatMitigation;

    public CVEBean(KernelCVE cve, boolean isFixed) {
        this.date = cve.getLastModified();
        this.cveid = cve.getId();
        this.source = "LinuxKernelCVEs";
        this.cvssScore = cve.getCvssScore();
        this.status = isFixed ? "Fixed" : "Unfixed";
        this.patch = cve.getFixes();
        this.debianMitigation = new DebianMitigator().searchMitigation(cveid);
        this.ubuntuMitigation = new UbuntuMitigator().searchMitigation(cveid);
        this.redHatMitigation = new RedHatMitigator().searchMitigation(cveid);
    }
}
