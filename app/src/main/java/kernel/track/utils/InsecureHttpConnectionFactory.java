package kernel.track.utils;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;

import org.eclipse.jgit.transport.http.HttpConnection;
import org.eclipse.jgit.transport.http.HttpConnectionFactory;
import org.eclipse.jgit.transport.http.JDKHttpConnectionFactory;
import org.eclipse.jgit.util.HttpSupport;


public class InsecureHttpConnectionFactory implements HttpConnectionFactory {
    @Override
    public HttpConnection create(URL url) throws IOException {
      return create(url, null);
    }

    @Override
    public HttpConnection create(URL url, Proxy proxy) throws IOException {
      HttpConnection connection = new JDKHttpConnectionFactory().create(url, proxy);
      HttpSupport.disableSslVerify(connection);
      return connection;
    }
}