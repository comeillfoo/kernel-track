package kernel.track.mitigators;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

public class RedHatMitigator extends StubMitigator {
    private String trackerURL = "https://security-tracker.debian.org/tracker/";

    @Override
    public String searchMitigation(String cveid) {
        final String html = getHTML(trackerURL, cveid);
        if (html.isBlank()) return "";
        final Document cvePage = Jsoup.parse(html);
        final Element mitigationSection = cvePage.selectFirst("section#cve-details-mitigation");
        if (mitigationSection == null) return "";
        final Element mitigationNotes = mitigationSection.selectFirst("div");
        if (mitigationNotes == null) return "";
        return mitigationNotes.text();
    }
}
