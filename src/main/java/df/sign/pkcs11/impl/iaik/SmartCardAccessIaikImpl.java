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
package df.sign.pkcs11.impl.iaik;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import df.sign.SignUtils;
import df.sign.pkcs11.CertificateData;
import df.sign.pkcs11.SmartCardAccessI;
import df.sign.utils.IOUtils;
import df.sign.utils.X509Utils;

public class SmartCardAccessIaikImpl implements SmartCardAccessI{
    
    private Module pkcs11Module = null;
    private Session session = null;
    private String wrapperPath = null;
    
    private void prepareWrapper() throws Exception, Error{
        if(wrapperPath!=null)
            return;
        
        String OS = System.getProperty("os.name").toLowerCase();
        String JVMArch = System.getProperty("os.arch");
        String wrapperName = "";
        
        if(OS.startsWith("windows")){
            if(JVMArch.equals("x86"))
                wrapperName = "PKCS11Wrapper32.dll";
            else
                wrapperName = "PKCS11Wrapper64.dll";
        }
        if(OS.startsWith("linux")){
            if(JVMArch.contains("64"))
                wrapperName = "libpkcs11wrapper64.so";
            else
                wrapperName = "libpkcs11wrapper32.so";
        }
        if(OS.startsWith("mac"))
            wrapperName = "libpkcs11wrapper.jnilib";
        
        if(wrapperName.equals(""))
            throw new Exception("Impossible to detect which PKCS11Wrapper library to use for the OS '"+OS+"' and architecture '"+JVMArch+"'");
        
        InputStream is = this.getClass().getResourceAsStream(wrapperName);
        if(is==null)
            throw new Exception("The library " + wrapperName + " is not present in the jar");
        
        wrapperPath = System.getProperty("java.io.tmpdir") + wrapperName;
        OutputStream ou = new FileOutputStream(wrapperPath);
        IOUtils.copyInputStreamToOutputStream(is, ou);
        ou.close();
        is.close();        
    }

    public long[] connectToLibrary(String library) throws Exception, Error{
        System.out.println("Connection to " + library);
        
        prepareWrapper();
        pkcs11Module = Module.getInstance(library, wrapperPath);
        pkcs11Module.initialize(null);
        
        Slot[] slotList = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        if(slotList.length==0)
            throw new Exception("Unable to find smart card using library " + library);

        ArrayList<Long> retArrLst = new ArrayList<Long>();
        
        long CKM_RSA_PKCS = new Long(0x00000001);
        
        for(Slot slot:slotList){
            try{        
                Mechanism[] mechanismList = slot.getToken().getMechanismList();
                long[] mechLst = new long[mechanismList.length];
                for(int i=0;i<mechanismList.length;i++)
                    mechLst[i] = mechanismList[i].getMechanismCode();
                
                if(SignUtils.isContainedIntoArray(CKM_RSA_PKCS, mechLst))
                    if(slot.getToken().getMechanismInfo(new Mechanism(CKM_RSA_PKCS)).isSign())
                        retArrLst.add(slot.getSlotID());
            }catch(Exception e){}catch(Error e){}
        }
        
        if(retArrLst.size()==0)
            throw new Exception("No smartcards found supporting signing with mechanism RSA_PKCS using library " + library);
        
        long[] ret = new long[retArrLst.size()];
        for(int i=0;i<retArrLst.size();i++)
            ret[i] = retArrLst.get(i);
        
        return ret;
    }
    
    private Slot getSlot(long slotID) throws Exception, Error{
        if(pkcs11Module==null)
            throw new Exception("pkcs11Module not initialized");
        Slot[] slotList = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        for(Slot slot:slotList)
            if(slot.getSlotID()==slotID)
                return slot;
        throw new Exception("Slot not found");
    }
    
    public long getPinMinLength(long slotID) throws Exception, Error{
        return getSlot(slotID).getToken().getTokenInfo().getMinPinLen();
    }
    
    public long getPinMaxLength(long slotID) throws Exception, Error{
        return getSlot(slotID).getToken().getTokenInfo().getMaxPinLen();
    }
    
    public ArrayList<CertificateData> getCertificateList(long slotID) throws Exception, Error{
        ArrayList<CertificateData> ret = new ArrayList<CertificateData>();
        
        session = getSlot(slotID).getToken().openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
        try {
            session.findObjectsInit(new X509PublicKeyCertificate());
            iaik.pkcs.pkcs11.objects.Object[] publicKeyCertificateObjectList = session.findObjects(1024);
    
            for(iaik.pkcs.pkcs11.objects.Object publicKeyCertificateObject : publicKeyCertificateObjectList){
                X509PublicKeyCertificate publicKeyCertificate = (X509PublicKeyCertificate) publicKeyCertificateObject;
                byte[] id = publicKeyCertificate.getId().getByteArrayValue();
                byte[] label = publicKeyCertificate.getLabel().toString(false).getBytes();
                byte[] certBytes = publicKeyCertificate.getValue().getByteArrayValue();
                X509Certificate cert = X509Utils.getX509Certificate(certBytes);
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
            session.closeSession();
            session = null;
        }
    }
    
    public long login(long slotID, String pin) throws Exception, Error{
        Token token = getSlot(slotID).getToken();
        session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
        if (token.getTokenInfo().isLoginRequired()){
            if (token.getTokenInfo().isProtectedAuthenticationPath())
                session.login(Session.UserType.USER, null);
            else
                session.login(Session.UserType.USER, pin.toCharArray());
        }
        return session.getSessionHandle();
    }
    
    public byte[] signData(long sessionID, byte[] certId, byte[] certLabel, byte[] data) throws Exception, Error{
        if(session==null)
            throw new Exception("session not initialized");
        
        RSAPrivateKey privateKeyToUse = null;        
        session.findObjectsInit(new RSAPrivateKey());
        iaik.pkcs.pkcs11.objects.Object[] privateKeyObjectList = session.findObjects(1024);
        
        for(iaik.pkcs.pkcs11.objects.Object privateKeyObject : privateKeyObjectList){
            RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyObject;
            byte[] id = privateKey.getId().getByteArrayValue();
            byte[] label = privateKey.getLabel().toString(false).getBytes();
            
            if(Arrays.equals(id, certId) || Arrays.equals(label, certLabel))
                privateKeyToUse = privateKey;
        }
        
        if(privateKeyToUse==null)
            throw new Exception("Impossible to identify a private key using the provided ID or LABEL");
        if(!privateKeyToUse.getSign().getBooleanValue())
            throw new Exception("The identified private key did not support supports signatures with appendix");
        
        session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), privateKeyToUse);
        byte[] signature = session.sign(data);
        return signature;
    }
    
    public void closeSession(long sessionID){
        try{
            if(session!=null)
                session.logout();
        }catch(Exception e){}catch(Error e){}
        
        try{
            if(session!=null)
                session.closeSession();
        }catch(Exception e){}catch(Error e){}
        
        session = null;
    }

    public void disconnectLibrary(){
        try{
            if(pkcs11Module!=null)
                pkcs11Module.finalize(null);
        }catch(Exception e){}catch(Error e){}
        
        pkcs11Module = null;
    }
    
    /*
    public static void main(String[] args) {
        try{
            SmartCardAccessIaikImpl cardManager = new SmartCardAccessIaikImpl();
            long[] slotList = cardManager.connectToLibrary("C:\\WINDOWS\\System32\\bit4ipki.dll");
            ArrayList<CertificateData> certificateDataList = cardManager.getCertificateList(slotList[0]);
            long sessionHandle = cardManager.login(slotList[0], "");
            CertificateData certificateData = certificateDataList.get(0);
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
