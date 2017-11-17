/*
    Websocket Smartcard Signer
    Copyright (C) 2017  Damiano Falcioni (damiano.falcioni@gmail.com)
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. 
 */
package df.sign.utils;

import java.io.DataOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class NETUtils {
    
    public static byte[] sendHTTPPOST(String url, String dataToSend, ArrayList<String[]> htmlHeaderList, boolean ignoreSSLSelfSigned, boolean ignoreSSLWrongCN) throws Exception{
        return sendHTTP(url, "POST", dataToSend, htmlHeaderList, ignoreSSLSelfSigned, ignoreSSLWrongCN);
    }
    
    public static byte[] sendHTTPGET(String url, ArrayList<String[]> htmlHeaderList, boolean ignoreSSLSelfSigned, boolean ignoreSSLWrongCN) throws Exception{
        return sendHTTP(url, "GET", null, htmlHeaderList, ignoreSSLSelfSigned, ignoreSSLWrongCN);
    }
    
    public static byte[] sendHTTP(String url, String mode, String dataToSend, ArrayList<String[]> htmlHeaderList, boolean ignoreSSLSelfSigned, boolean ignoreSSLWrongCN) throws Exception{
        
        System.setProperty("java.net.useSystemProxies", "true");
        
        if(ignoreSSLSelfSigned){
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
            };
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        }
        if(ignoreSSLWrongCN){
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
                    return true;
                }
            };
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        }
        
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        
        if(htmlHeaderList != null)
            for(String[] htmlHeader:htmlHeaderList)
                if(htmlHeader.length==2)
                    connection.setRequestProperty(htmlHeader[0], htmlHeader[1]);

        if(mode.equals("POST") && dataToSend != null){
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Length", "" + Integer.toString(dataToSend.getBytes().length));
            
            DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
            wr.writeBytes(dataToSend);
            wr.flush();
            wr.close();
        }
        
        byte[] output = new byte[0];
        if(connection.getResponseCode() >= 400)
            output = IOUtils.toByteArray(connection.getErrorStream());
        else
            output = IOUtils.toByteArray(connection.getInputStream());

        connection.disconnect();
        
        return output;
    }
}
