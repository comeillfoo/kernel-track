package kernel.track.mitigators;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

public class DebianMitigator extends StubMitigator {
    private String trackerURL = "https://security-tracker.debian.org/tracker/";

    @Override
    public String searchMitigation(String cveid) {
        final String html = getHTML(trackerURL, cveid);
        if (html.isBlank()) return "";
        Document cvePage = Jsoup.parse(html);
        Element notesHeader = cvePage.selectFirst("h2:contains(Notes)");
        if (notesHeader == null) return "";
        return notesHeader.nextElementSibling().text();
    }

}