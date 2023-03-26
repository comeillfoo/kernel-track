package kernel.track.mitigators;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class UbuntuMitigator extends StubMitigator {
    private String trackerURL = "https://ubuntu.com/security/";

    @Override
    public String searchMitigation(String cveid) {
        final String html = getHTML(trackerURL, cveid);
        if (html.isBlank()) return "";
        final Document cvePage = Jsoup.parse(html);
        final Element notesHeader = cvePage.selectFirst("h2:contains(Notes)");
        if (notesHeader == null) return "";
        final Element table = notesHeader.nextElementSibling();
        if (table == null) return "";
        final Elements rows = table.select("tr");
        if (rows.size() <= 1) return "";
        final Element noteRow = rows.get(1);
        final Element note = noteRow.select("td").last();
        if (note == null) return "";
        return note.text();
    }
}
