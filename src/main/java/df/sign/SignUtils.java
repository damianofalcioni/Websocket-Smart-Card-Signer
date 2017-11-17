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
package df.sign;

import java.io.File;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import df.sign.pkcs11.CertificateData;
import df.sign.utils.StringUtils;
import df.sign.utils.X509Utils;

@SuppressWarnings("restriction")
public class SignUtils {
    
    public static final String[] standardDllList = new String[]{"incryptoki2.dll", "bit4ipki.dll", "bit4opki.dll", "bit4xpki.dll", "OCSCryptoki.dll", "asepkcs.dll", "SI_PKCS11.dll", "cmP11.dll", "cmP11_M4.dll", "IpmPki32.dll", "IPMpkiLC.dll", "IpmPkiLU.dll", "bit4cpki.dll", "bit4p11.dll", "asepkcs.dll", "PKCS11.dll", "eTPKCS11.dll", "SSC_PKCS11.dll", "inp11lib.dll", "opensc-pkcs11.dll", "libbit4opki.so", "libbit4spki.so", "libbit4p11.so", "libbit4ipki.so", "opensc-pkcs11.so", "libeTPkcs11.so", "libopensc.dylib", "libbit4xpki.dylib", "libbit4ipki.dylib", "libbit4opki.dylib", "libASEP11.dylib", "libeTPkcs11.dylib"};    
    private static ArrayList<String[]> mapCardInfoList = new ArrayList<String[]>();
    static {
        mapCardInfoList.add(new String[]{"Carta Raffaello 111", "bit4ipki.dll%incryptoki2.dll%libbit4ipki.so%libbit4ipki.dylib", "3BFF1800FF8131FE55006B02090200011101434E531131808E", "http://www.cartaraffaello.it/AreaDownload/tabid/80/language/it-IT/Default.aspx"});
        mapCardInfoList.add(new String[]{"Carta Raffaello 611", "bit4opki.dll%libbit4opki.so%libbit4opki.dylib", "3BFF1800008131FE45006B04050100012101434E5310318059", "http://www.cartaraffaello.it/AreaDownload/tabid/80/language/it-IT/Default.aspx"});
    }
    
    public static ArrayList<CertificateData> processCertificateList(ArrayList<CertificateData> certificateDataList){
        ArrayList<CertificateData> nonRepudList = new ArrayList<CertificateData>();
        ArrayList<CertificateData> signList = new ArrayList<CertificateData>();
        
        for(CertificateData certificateData:certificateDataList){
            if(X509Utils.checkIsNonRepudiation(certificateData.cert))
                nonRepudList.add(certificateData);
            if(X509Utils.checkIsForSigning(certificateData.cert))
                signList.add(certificateData);
        }
        if(nonRepudList.size()!=0)
            return nonRepudList;
        
        if(signList.size()!=0)
            return signList;
        
        return new ArrayList<CertificateData>();
    }
    
    public static byte[] calculateHASH(String digestOID, byte[] data) throws Exception{
        String digestName = "";
        
        try{
            if(Security.getProvider("BC") == null)
                Security.addProvider(new BouncyCastleProvider());
            
            if(digestOID.equals(CMSSignedDataGenerator.DIGEST_MD5))
                digestName = "MD5";
            if(digestOID.equals(CMSSignedDataGenerator.DIGEST_SHA1))
                digestName = "SHA-1";
            if(digestOID.equals(CMSSignedDataGenerator.DIGEST_SHA256))
                digestName = "SHA-256";
            if(digestOID.equals(CMSSignedDataGenerator.DIGEST_SHA384))
                digestName = "SHA-384";
            if(digestOID.equals(CMSSignedDataGenerator.DIGEST_SHA512))
                digestName = "SHA-512";
            
            if(digestName.equals(""))
                throw new Exception("Unsupported digestOID");
            
            MessageDigest md = MessageDigest.getInstance(digestName, "BC");
            md.update(data);
            
            byte[] hash = md.digest();

            return hash;
        }catch(Exception e){
            throw new Exception("Error on the generation for the Hash "+digestName+":\n"+e.getMessage());
        }
    }
    
    public static boolean isContainedIntoArray(long element, long[] elementList){
        for(Object el:elementList)
            if(el.equals(element))
                return true;
        return false;
    }
    
    public static String getLibraryFullPath(String pkcs11Library){
        if(new File(pkcs11Library).exists())
            return pkcs11Library;
        
        String OS = System.getProperty("os.name").toLowerCase();
        
        String[] pathList = new String[0];
        
        if(OS.contains("windows")){
            if(pkcs11Library.toLowerCase().endsWith("dll")){
                String systemRoot = System.getenv("SystemRoot");
                String programFiles = System.getenv("ProgramFiles");
                pathList = new String[]{
                    systemRoot + "\\pkcs11Libs\\" + pkcs11Library,
                    programFiles + "\\Oberthur Technologies\\AWP\\DLLs\\" + pkcs11Library,
                    systemRoot + "\\" + pkcs11Library,
                    systemRoot + "\\System32\\" + pkcs11Library
                };
            }
        } else {
            if(pkcs11Library.toLowerCase().endsWith("so") || pkcs11Library.toLowerCase().endsWith("dylib")){
                pathList = new String[]{
                    "/usr/lib/" + pkcs11Library,
                    "/usr/lib/pkcs11/" + pkcs11Library,
                    "/usr/lib/PKCS11/" + pkcs11Library,
                    "/usr/local/lib/" + pkcs11Library,
                    "/lib/" + pkcs11Library,
                    "/var/lib/" + pkcs11Library,
                    "/Library/" + pkcs11Library,
                    "/Library/OpenSC/lib/" + pkcs11Library,
                    "/Library/bit4id/pkcs11/" + pkcs11Library
                };
            }
        }
        
        for(String path:pathList)
            if(new File(path).exists())
                return path;
        
        return null;
    }

    public static String[] checkJarConflicts(){
        String ret = "";
        String[] dirs = System.getProperty("java.ext.dirs").split(";");
        for(String dir:dirs){
            File[] files = new File(dir).listFiles();
            if(files == null)
                continue;
            for(File file:files){
                if(file.isDirectory())
                    continue;
                String fileName = file.getName().toLowerCase();
                if(fileName.endsWith(".jar") && (fileName.contains("bcprov") || fileName.contains("bcpkix") || fileName.contains("itextpdf")  || fileName.contains("jna") || fileName.contains("iaik")))
                    ret += file.getAbsolutePath() + ";";
            }
        }
        if(ret == "")
            return new String[0];
        return ret.split(";");
    }
    
    public static ArrayList<String> getConnectedCardATR(){
        ArrayList<String> ret = new ArrayList<String>();
        try{
            List<CardTerminal> terminalList = TerminalFactory.getDefault().terminals().list();
            
            for(CardTerminal terminal:terminalList)
                if(terminal.isCardPresent()){
                    javax.smartcardio.Card card = terminal.connect("*");
                    ret.add(StringUtils.toHexString(card.getATR().getBytes()));
                    card.disconnect(false);
                }
        }catch(Exception ex){}
        return ret;
    }
    
    public static String[] getCardInfo(String atr){
        for(String[] mapCardInfo:mapCardInfoList)
            if(atr.equals(mapCardInfo[2]))
                return mapCardInfo;
        return null;
    }
    
    public static String getCardTypeFromDLL(String dll){
        for(String[] mapCardInfo:mapCardInfoList)
            if(mapCardInfo[1].contains(dll))
                return mapCardInfo[0];
        return "";
    }
    
    public static String getIDFromSubject(String certificateSubject){
        String ret = "";
        String CN = certificateSubject.substring(certificateSubject.indexOf("CN=")+3);
        int indexCN = CN.indexOf(',');
        if(indexCN == -1)
            indexCN = CN.length();
        CN = CN.substring(0, indexCN);
        if(CN.contains("/"))
            CN = CN.split("/")[0].substring(1);
        
        String O = "Not Defined";
        if(certificateSubject.contains("O=")){
            O = certificateSubject.substring(certificateSubject.indexOf("O=")+2);
            int indexO = O.indexOf(',');
            if(indexO == -1)
                indexO = O.length();
            O = O.substring(0, indexO);
            if(O.contains("/"))
                O = O.split("/")[0];
        }
        ret = CN + "    Org:" + O;
        return ret;
    }
    
    public static CertificateData getCertificateDataByID(String id, ArrayList<CertificateData> certList){
        for(CertificateData cert:certList)
            if(cert.id.equals(id))
                return cert;
        return null;
    }
    
    public static void playBeeps(int numBeeps){
        if(numBeeps<0)
            return;
        
        for(int i=0;i<numBeeps;i++){
            java.awt.Toolkit.getDefaultToolkit().beep();
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {} 
        }
    }
    
    public static byte[] base64Encode(byte[] data){
        return org.bouncycastle.util.encoders.Base64.encode(data);
    }
    
    public static byte[] base64Decode(byte[] data){
        return org.bouncycastle.util.encoders.Base64.decode(data);
    }
    
    public static Date getNTPDate() throws Exception{
        //FIXME: how to use system defined proxy here ?
        System.setProperty("java.net.useSystemProxies", "true");
        NTPUDPClient client = new NTPUDPClient();
        client.setDefaultTimeout(5000);
        TimeInfo response = client.getTime(InetAddress.getByName("pool.ntp.org"));
        return new Date(response.getReturnTime());
    }
}
