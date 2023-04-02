package kernel.track.models;

import com.opencsv.bean.CsvBindByPosition;

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
    @CsvBindByPosition(position = 0)
    private String date;

    @CsvBindByPosition(position = 1)
    private String cveid;

    @CsvBindByPosition(position = 2)
    private String source;

    @CsvBindByPosition(position = 3, locale = "ru-RU")
    private double cvssScore;

    @CsvBindByPosition(position = 4)
    private String description;

    @CsvBindByPosition(position = 5)
    private String status;

    @CsvBindByPosition(position = 6)
    private String patch;

    @CsvBindByPosition(position = 7)
    private String debianMitigation;

    @CsvBindByPosition(position = 8)
    private String ubuntuMitigation;

    @CsvBindByPosition(position = 9)
    private String redHatMitigation;

    public CVEBean(KernelCVE cve, boolean isFixed) {
        this.date = cve.getLastModified();
        this.cveid = cve.getId();
        this.source = "LinuxKernelCVEs";
        this.cvssScore = cve.getCvssScore();
        this.description = cve.getNvdText();
        this.status = isFixed ? "Fixed" : "Unfixed";
        this.patch = cve.getFixes();
        this.debianMitigation = ""; // new DebianMitigator().searchMitigation(cveid);
        this.ubuntuMitigation = ""; // new UbuntuMitigator().searchMitigation(cveid);
        this.redHatMitigation = ""; // new RedHatMitigator().searchMitigation(cveid);
    }

    public static final String[] HEADER = new String[] {
        "Last Modified", "CVE", "Source", "CVSS Score",
        "Description", "Status", "Patch", "Debian Mitigation",
        "Ubuntu Mitigation", "Red Hat Mitigation"
    };

    public static CVEBean fixedOf(KernelCVE cve) {
        return new CVEBean(cve, true);
    }

    public static CVEBean unfixedOf(KernelCVE cve) {
        return new CVEBean(cve, false);
    }
}
