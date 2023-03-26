package kernel.track.mitigators;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

public class StubMitigator implements Mitigator {
    protected String getHTML(String domain, String cveid) {
        try {
            final String uri = domain + cveid;
            URLConnection conn = new URL(uri).openConnection();

            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line = "";
            while ((line = br.readLine()) != null)
                sb.append(line);
            br.close();
            return sb.toString();
        } catch (IOException io) {
            io.printStackTrace();
            return "";
        }
    }

    @Override
    public String searchMitigation(String cveid) {
        return "";
    }
}
