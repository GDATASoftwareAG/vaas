package de.gdata.vaas;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public class SSLContextFactory {
    public static SSLContext create(boolean ignoreTlsErrors) {
        var logger = Logger.getLogger(SSLContextFactory.class.getName());
        try {
            if (!ignoreTlsErrors) {
                return SSLContext.getDefault();
            }

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { UnsafeX509ExtendedTrustManager.getInstance() }, null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            logger.log(Level.SEVERE, "Unable to init SSLContext", e);
            return null;
        }
    }
}
