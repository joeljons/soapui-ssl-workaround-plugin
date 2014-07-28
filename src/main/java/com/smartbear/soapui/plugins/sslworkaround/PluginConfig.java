package com.smartbear.soapui.plugins.sslworkaround;

import com.eviware.soapui.SoapUI;
import com.eviware.soapui.plugins.PluginAdapter;
import com.eviware.soapui.plugins.PluginConfiguration;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

@PluginConfiguration(groupId = "com.smartbear.soapui.plugins", name = "SSL Workaround Plugin", version = "1.0.0",
        autoDetect = true, description = "Make REST Discovery stop complaining about self signed certificates and expired certificates (no config).",
        infoUrl = "https://github.com/joeljons/soapui-ssl-workaround-plugin")
public class PluginConfig extends PluginAdapter {
    @Override
    public void initialize() {
        disableSslSecurity();
    }

    private void disableSslSecurity() {
        // Create a trust manager that does not validate certificate chains
        final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Create a hostname verifier that accept all hostnames
        final HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String string, SSLSession ssls) {
                return true;
            }
        };

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
            SoapUI.log.info("SSL Workaround Plugin initialized");
        } catch (GeneralSecurityException e) {
            SoapUI.logError(e, "SSL Workaround Plugin initialization error");
        }
    }
}
