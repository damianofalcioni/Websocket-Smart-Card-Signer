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
package df.sign.pkcs11.impl.jna;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import org.pkcs11.jacknji11.C;
import org.pkcs11.jacknji11.CE;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.jna.JNA;

import df.sign.SignUtils;
import df.sign.pkcs11.CertificateData;
import df.sign.pkcs11.SmartCardAccessI;
import df.sign.utils.StringUtils;
import df.sign.utils.X509Utils;

public class SmartCardAccessJnaImpl implements SmartCardAccessI {

    public long[] connectToLibrary(String library) throws Exception, Error{
        System.out.println("Connection to " + library);
        
        C.NATIVE = new JNA(library);
        CE.Initialize();
        long[] slotList = CE.GetSlotList(true);
        if(slotList.length==0)
            throw new Exception("Unable to find smart card using library " + library);

        ArrayList<Long> retArrLst = new ArrayList<Long>();
        for(long slot:slotList){
            try{
                long[] mechLst = CE.GetMechanismList(slot);
                if(SignUtils.isContainedIntoArray(CKM.RSA_PKCS, mechLst)){
                    CK_MECHANISM_INFO myMechanismInfo = (CK_MECHANISM_INFO) CE.GetMechanismInfo(slot, CKM.RSA_PKCS);
                    if(myMechanismInfo.isFlagSet(CK_MECHANISM_INFO.CKF_SIGN))
                        retArrLst.add(slot);
                }
            }catch(Exception e){}catch(Error e){}
        }
        
        if(retArrLst.size()==0)
            throw new Exception("No smartcards found supporting signing with mechanism RSA_PKCS using library " + library);
        
        long[] ret = new long[retArrLst.size()];
        for(int i=0;i<retArrLst.size();i++)
            ret[i] = retArrLst.get(i);
        
        return ret;
    }
    
    public long getPinMinLength(long slotID) throws Exception, Error{
        return CE.GetTokenInfo(slotID).ulMinPinLen;
    }
    
    public long getPinMaxLength(long slotID) throws Exception, Error{
        return CE.GetTokenInfo(slotID).ulMaxPinLen;
    }
    
    public ArrayList<CertificateData> getCertificateList(long slotID) throws Exception{
        ArrayList<CertificateData> ret = new ArrayList<CertificateData>();

        long sessionID = CE.OpenSession(slotID, (CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION), null, null);
        try {
            long[] objectIdList = CE.FindObjects(sessionID, new CKA[]{ new CKA(CKA.CLASS, CKO.CERTIFICATE)});
            
            for(long objectId:objectIdList){
                CKA[] ckaId = new CKA[]{ new CKA(CKA.ID, new byte[255])};
                CE.GetAttributeValue(sessionID, objectId, ckaId);
                byte[] id = StringUtils.trim(ckaId[0].getValue());
                
                CKA[] ckaLabel = new CKA[]{ new CKA(CKA.LABEL, new byte[255])};
                CE.GetAttributeValue(sessionID, objectId, ckaLabel);
                byte[] label = StringUtils.trim(ckaLabel[0].getValue());
                
                CKA[] ckaValue = new CKA[]{ new CKA(CKA.VALUE, new byte[2048])};
                CE.GetAttributeValue(sessionID, objectId, ckaValue);
                X509Certificate cert = X509Utils.getX509Certificate(ckaValue[0].getValue());
                
                if(!(cert.getKeyUsage()[0] || cert.getKeyUsage()[1]))
                    continue;
                CertificateData cd = new CertificateData();
                cd.certID = id;
                cd.certLABEL = label;
                cd.cert = cert;
                ret.add(cd);
            }
            
            return ret;
        } finally {
            CE.CloseSession(sessionID);
        }
    }
    
    public long login(long slotID, String pin) throws Exception, Error{
        
        long session = CE.OpenSession(slotID, (CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION), null, null);
        CK_TOKEN_INFO tokenInfo = (CK_TOKEN_INFO) CE.GetTokenInfo(slotID);
        
        if(tokenInfo.isFlagSet(CK_TOKEN_INFO.CKF_LOGIN_REQUIRED)){
            if(tokenInfo.isFlagSet(CK_TOKEN_INFO.CKF_PROTECTED_AUTHENTICATION_PATH))
                CE.Login(session, CKU.USER, null);
            else
                CE.Login(session, CKU.USER, pin.getBytes());
        }
        return session;
    }
    
    public byte[] signData(long sessionID, byte[] certId, byte[] certLabel, byte[] data) throws Exception, Error{
        
        long[] privateKeyObjectIdList = CE.FindObjects(sessionID, new CKA[]{ new CKA(CKA.CLASS, CKO.PRIVATE_KEY)});
        long privateKeyObjectIdToUse = -1;
        
        for(long privateKeyObjectId : privateKeyObjectIdList) {
            CKA[] ckaId = new CKA[]{ new CKA(CKA.ID, new byte[255])};
            CE.GetAttributeValue(sessionID, privateKeyObjectId, ckaId);
            byte[] id = StringUtils.trim(ckaId[0].getValue());
            
            CKA[] ckaLabel = new CKA[]{ new CKA(CKA.LABEL, new byte[255])};
            CE.GetAttributeValue(sessionID, privateKeyObjectId, ckaLabel);
            byte[] label = StringUtils.trim(ckaLabel[0].getValue());
            
            if(Arrays.equals(id, certId) || Arrays.equals(label, certLabel))
                privateKeyObjectIdToUse = privateKeyObjectId;
        }
        
        if(privateKeyObjectIdToUse==-1)
            throw new Exception("Impossible to identify a private key using the provided ID or LABEL");
        
        CKA[] ckaSign = new CKA[]{ new CKA(CKA.SIGN, new byte[255])};
        CE.GetAttributeValue(sessionID, privateKeyObjectIdToUse, ckaSign);
        boolean isForSign = ckaSign[0].getValueBool();
        if(!isForSign)
            throw new Exception("The identified private key did not support supports signatures with appendix");
        
        byte[] signature = CE.Sign(sessionID,  new CKM(CKM.RSA_PKCS, null), privateKeyObjectIdToUse, data);
        return signature;
    }
    
    public void closeSession(long sessionID){
        try{
            CE.Logout(sessionID);
        }catch(Exception e){}catch(Error e){}
        
        try{
            CE.CloseSession(sessionID);
        }catch(Exception e){}catch(Error e){}
    }

    public void disconnectLibrary(){
        try{
            CE.Finalize();
        }catch(Exception e){}catch(Error e){}
    }
    
    /*
    public static void main(String[] args) {
        try{
            SmartCardAccessJnaImpl cardManager = new SmartCardAccessJnaImpl();
            long[] slotList = cardManager.connectToLibrary("C:\\WINDOWS\\System32\\bit4ipki.dll");
            ArrayList<CertificateData> certificateDataList = cardManager.getCertificateList(slotList[0]);
            long sessionHandle = cardManager.login(slotList[0], "");
            CertificateData certificateData = certificateDataList.get(1);
            System.out.println(certificateData.cert.getSubjectDN().getName());
            
            byte[] dataTest = "test".getBytes();
            byte[] hashToSign = SignUtils.calculateHASH(org.bouncycastle.cms.CMSSignedDataGenerator.DIGEST_SHA256, dataTest);
            hashToSign = df.sign.cms.CMSSignedDataWrapper.getDigestInfoToSign(org.bouncycastle.cms.CMSSignedDataGenerator.DIGEST_SHA256, hashToSign);
            
            byte[] signed = cardManager.signData(sessionHandle, certificateData.certID, certificateData.certLABEL, hashToSign);
            cardManager.closeSession(sessionHandle);
            cardManager.disconnectLibrary();
            
            java.security.Signature sig = java.security.Signature.getInstance("SHA256WithRSA", "BC");
            sig.initVerify(certificateData.cert.getPublicKey());
            sig.update(dataTest);
            System.out.println("Signature verified: " + sig.verify(signed));
            
        }catch(Exception e){e.printStackTrace();}catch(Error e){e.printStackTrace();}
    }
    */
}
