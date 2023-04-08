package kernel.track.mitigators;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StubMitigator implements Mitigator {
    private final Logger logger = LogManager.getLogger(getClass());

    protected String getHTML(String domain, String cveid) {
        final String uri = domain + cveid;
        URLConnection conn = null;
        try {
            conn = new URL(uri).openConnection();
        } catch (IOException ioe) {
            logger.error(String.format("[%s]: error while opening connection to %s", cveid, uri), ioe);
            return "";
        }
        BufferedReader br = null;
        StringBuilder sb = null;
        try {
            br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            sb = new StringBuilder();
            String line = "";
            while ((line = br.readLine()) != null)
                sb.append(line);
            br.close();
        } catch (IOException ioe) {
            logger.error(String.format("[%s]: error while ackquiring HTML at %s", cveid, uri), ioe);
            return "";
        }
        return sb.toString();
    }

    @Override
    public String searchMitigation(String cveid) {
        return "";
    }
}
