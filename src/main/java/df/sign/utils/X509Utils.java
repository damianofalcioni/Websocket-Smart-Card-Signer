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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.directory.InitialDirContext;

public class X509Utils {
    public static boolean checkValidity(X509Certificate cert, Date validUntill){
        try{
            if(validUntill!=null)
                cert.checkValidity(validUntill);
            else
                cert.checkValidity();

            return true;
        }catch(Exception e){}
        return false;
    }
    
    public static boolean checkIsForSigning(X509Certificate cert){
        if(cert.getKeyUsage()[0])
            return true;
        return false;
    }
    
    public static boolean checkIsNonRepudiation(X509Certificate cert){
        if(cert.getKeyUsage()[1])
            return true;
        return false;
    }
    
    public static X509Certificate getX509Certificate(byte[] x509Certificate) {
        try{
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(x509Certificate));
        }catch(Exception e){e.printStackTrace();}
        return null;
    }
    
    public static String getCN(X509Certificate cert){
        String certificateSubject = cert.getSubjectDN().getName();
        if(certificateSubject.indexOf("CN=") == -1)
            return "";
        String CN = certificateSubject.substring(certificateSubject.indexOf("CN=")+3);
        int lastIndex = CN.indexOf(',');
        if(lastIndex == -1)
            lastIndex = CN.length();
        CN = CN.substring(0, lastIndex);
        return CN;
    }
    
    public static String getCFFromCertSubject(String certificateSubject){
        String cfRegexPattern = "\\p{Upper}\\p{Upper}\\p{Upper}\\p{Upper}\\p{Upper}\\p{Upper}\\p{Digit}\\p{Digit}\\p{Upper}\\p{Digit}\\p{Digit}\\p{Upper}\\p{Digit}\\p{Digit}\\p{Digit}\\p{Upper}";

        if(certificateSubject.contains("CN=")){
            String CN = certificateSubject.substring(certificateSubject.indexOf("CN=")+3);
            int lastIndex = CN.length();
            if(CN.indexOf(',')!=-1)
                lastIndex = CN.indexOf(',');
            CN = CN.substring(0, lastIndex);
            if(CN.contains("/"))
                CN=CN.split("/")[0].substring(1);
            if(CN.matches(cfRegexPattern))
                return CN;
        }
        
        if(certificateSubject.contains("SERIALNUMBER=")){
            String SERIALNUMBER = certificateSubject.substring(certificateSubject.indexOf("SERIALNUMBER=")+13);
            int lastIndex = SERIALNUMBER.length();
            if(SERIALNUMBER.indexOf(',')!=-1)
                lastIndex = SERIALNUMBER.indexOf(',');
            SERIALNUMBER = SERIALNUMBER.substring(0, lastIndex);
            if(SERIALNUMBER.contains(":"))
                SERIALNUMBER = SERIALNUMBER.split(":")[1];
            if(SERIALNUMBER.matches(cfRegexPattern))
                return SERIALNUMBER;
        }
        return "";
    }
    
    public static ArrayList<String> getDistributionPointUrls(X509Certificate cert){
        
        ArrayList<String> ret = new ArrayList<String>();
        
        try{
            String data = cert.toString();
            
            if(data.indexOf("CRLDistributionPoints") == -1)
                return ret;
            
            data = data.substring(data.indexOf("CRLDistributionPoints"));
            data = data.substring(0, data.indexOf("]]") + 2);
            
            while(data.indexOf("URIName") != -1){
                data = data.substring(data.indexOf("URIName") + 9);
                
                String url = data.substring(0, data.indexOf("]"));
                
                if(url.contains(", URIName: ")){
                    String[] urlTmpList = url.split(", URIName: ");
                    for(String urlTmp:urlTmpList)
                        ret.add(urlTmp);
                }else
                    ret.add(url);
                
                data = data.substring(data.indexOf("]") + 1);
            }
        }catch(Exception ex){ex.printStackTrace();}
        
        return ret;
    }
    
    public static X509CRL getX509CRLFromURL(String url){
        try{
            System.setProperty("java.net.useSystemProxies", "true");
            InputStream inStream = null;
            try{
                if(url.toLowerCase().startsWith("ldap")){
                    Map<String, String> env = new Hashtable<String, String>();
                    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                    env.put(Context.PROVIDER_URL, url);
                    byte[] val = (byte[]) new InitialDirContext((Hashtable<String, String>)env).getAttributes("").get("certificateRevocationList;binary").get();
                    if ((val == null) || (val.length == 0))
                        throw new Exception("Can not download CRL from: " + url);
                    inStream = new ByteArrayInputStream(val);
                } else{
                    inStream = new URL(url).openStream();
                }
                System.out.println("CRL download correctly from : " + url);
            }catch(Exception e){throw new Exception("Can not download CRL from: " + url + "\n" + e.getMessage());}
            
            X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(inStream);
            inStream.close();
            
            return crl;
        }catch(Exception ex){ex.printStackTrace();}
        return null;
    }
    
    public static boolean checkIsSelfSigned(X509Certificate cert){
        try{
            cert.verify(cert.getPublicKey());
            return true;
        }catch(Exception ex){}
        return false;
    }
    
    public static boolean checkIsRevoked(X509Certificate cert){
        ArrayList<String> crlDPUrlList = getDistributionPointUrls(cert);
        X509CRL x509CRL = null;
        for(String crlDPUrl: crlDPUrlList){
            if(crlDPUrl.toLowerCase().startsWith("ldap"))
                continue;
            x509CRL = getX509CRLFromURL(crlDPUrl);
            if(x509CRL != null)
                break;
        }
        if(x509CRL == null)
            for(String crlDPUrl: crlDPUrlList){
                if(!crlDPUrl.toLowerCase().startsWith("ldap"))
                    continue;
                x509CRL = getX509CRLFromURL(crlDPUrl);
                if(x509CRL != null)
                    break;
            }
        try{
            if(x509CRL == null)
                throw new Exception("Impossible to get the Certificate Revocation List from the URLs provided.");
        }catch(Exception ex){ex.printStackTrace();return false;}
        
        return x509CRL.isRevoked(cert);
    }
    
    public static void checkAllOnCertificate(X509Certificate cert) throws Exception{
        boolean ok = true;
        String msg = "\n";
        String subj = getCFFromCertSubject(cert.getSubjectDN().getName());
        if(checkIsSelfSigned(cert)){
            ok = false;
            msg += "The certificate is Self Signed\n";
        }
        if(!checkIsNonRepudiation(cert)){
            ok = false;
            msg += "The certificate is not valid for 'Non Repudiation'\n";
        }
        if(!checkValidity(cert, new Date())){
            ok = false;
            msg += "The certificate is currently expired\n";
        }
        if(checkIsRevoked(cert)){
            ok = false;
            msg += "The certificate has been revoked\n";
        }
        
        if(!ok)
            throw new Exception("Errors on validating certificate for " + subj + ":" + msg);
    }
}
