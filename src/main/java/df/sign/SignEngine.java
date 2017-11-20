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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cms.CMSSignedDataGenerator;

import df.sign.cms.CMSSignedDataWrapper;
import df.sign.cms.PKCS7Manager;
import df.sign.datastructure.Data;
import df.sign.datastructure.SignConfig;
import df.sign.pdf.PDFManager;
import df.sign.pkcs11.CertificateData;
import df.sign.pkcs11.SmartCardAccessI;

public class SignEngine {
    
    ArrayList<Data> dataToSignList = null;
    ArrayList<Data> dataSignedList = null;
    
    private SmartCardAccessI smartCardAccessManager = null;
    public String[] dllList = null;
    public ArrayList<CertificateData> certificateList = null;
    public boolean useNTPTime = false;
    
    public SignEngine(SmartCardAccessI smartCardAccessManager, String[] dllList) throws Exception{
        if(dllList == null || dllList.length==0)
            throw new Exception("Please provide one or more libraries to access the smart card");
        this.dllList = dllList;

        dataToSignList = new ArrayList<Data>();
        dataSignedList = new ArrayList<Data>();
        
        this.smartCardAccessManager = smartCardAccessManager;
        certificateList = new ArrayList<CertificateData>();
    }
    
    public SignEngine loadDataToSign(Data signData) throws Exception{
        if(signData.id == null || signData.id.isEmpty())
            throw new Exception("id must be defined");
        if(signData.data == null || signData.data.length == 0)
            throw new Exception("data must be defined");
        if(signData.config == null)
            throw new Exception("config must be defined");
        
        dataToSignList.add(signData);
        return this;
    }
    
    public SignEngine loadDataToSign(Data[] signDataList) throws Exception{
        for(Data signData : signDataList)
            loadDataToSign(signData);
        return this;
    }
    
    public SignEngine loadDataToSign(List<Data> signDataList) throws Exception{
        for(Data signData : signDataList)
            loadDataToSign(signData);
        return this;
    }

    public SignEngine cleanDataToSign(){
        dataToSignList = new ArrayList<Data>();
        return this;
    }
    
    public List<Data> getSignedData(){
        return dataSignedList;
    }
    
    public int getNumDataToSign(){
        return dataToSignList.size();
    }
    
    public SignEngine sign(CertificateData certData, String pin) throws Exception{
        if(certData == null)
            throw new Exception("certData can not be null");
        if(pin == null || pin.length()==0)
            throw new Exception("pin can not be empty");
        
        Date timeNow = new Date();
        if(useNTPTime)
            timeNow = SignUtils.getNTPDate();
        
        String digestOIDToUse = CMSSignedDataGenerator.DIGEST_SHA256;
        
        certData = checkAlternativeLibraries(pin, certData, digestOIDToUse);
        
        try {
            long[] slotList = smartCardAccessManager.connectToLibrary(certData.dll);
            if(!SignUtils.isContainedIntoArray(certData.slot, slotList))
                throw new Exception("Impossible to use the slot " + certData.slot + " with the library " + certData.dll);
            
            long sessionId = smartCardAccessManager.login(certData.slot, pin);
            try {
                for(Data dataToSign : dataToSignList){
                    
                    String contentId = dataToSign.id;
                    SignConfig signConfig = dataToSign.config;
                    
                    PDFManager pdfManager = null;
                    byte[] unsignedContent  = dataToSign.data;
                    byte[] dataToHash = unsignedContent;
                    
                    if(PKCS7Manager.isPKCS7File(unsignedContent)){
                        signConfig.saveAsPDF = false;
                        byte[] tmp = PKCS7Manager.extractData(unsignedContent);
                        if(tmp.length!=0)
                            dataToHash = tmp;
                    } else if(PDFManager.isAPdf(unsignedContent) && !signConfig.signPdfAsP7m){
                        signConfig.saveAsPDF = true;
                        pdfManager = new PDFManager(unsignedContent, certData.cert);
                        pdfManager.setDateTime(timeNow);
                        if(signConfig.visibleSignature)
                            pdfManager.setVisibleSignature(signConfig.pageNumToSign, signConfig.signPosition);
                        pdfManager.preClose();
                        dataToHash = pdfManager.getDataToHashAndSign();
                    }
                    
                    byte[] hash = SignUtils.calculateHASH(digestOIDToUse, dataToHash);
                    byte[] hashToSign = SignUtils.calculateHASH(digestOIDToUse, CMSSignedDataWrapper.getDataToSign(hash, timeNow, certData.cert));
                    hashToSign = CMSSignedDataWrapper.getDigestInfoToSign(digestOIDToUse, hashToSign);
                    
                    byte[] signature = smartCardAccessManager.signData(sessionId, certData.certID, certData.certLABEL, hashToSign);
                    
                    byte[] signedContent = null;
                    if(pdfManager == null){
                        signedContent = PKCS7Manager.buildPKCS7(digestOIDToUse, unsignedContent, certData.cert, signature, hash, timeNow);
                    }else{
                        pdfManager.buildSignedPDF(digestOIDToUse, signature, hash);
                        int csize = pdfManager.getContentsSize();
                        //The first signature is used only to evaluate csize, then the second signature is applied with the correct csize
                        pdfManager = new PDFManager(unsignedContent, certData.cert);
                        pdfManager.setDateTime(timeNow);
                        if(signConfig.visibleSignature)
                            pdfManager.setVisibleSignature(signConfig.pageNumToSign, signConfig.signPosition);
                        pdfManager.setContentsSize(csize);
                        pdfManager.preClose();
                        dataToHash = pdfManager.getDataToHashAndSign();
                        hash = SignUtils.calculateHASH(digestOIDToUse, dataToHash);
                        hashToSign = hash;
                        hashToSign = SignUtils.calculateHASH(digestOIDToUse, CMSSignedDataWrapper.getDataToSign(hash, timeNow, certData.cert));
                        hashToSign = CMSSignedDataWrapper.getDigestInfoToSign(digestOIDToUse, hashToSign);
                        signature = smartCardAccessManager.signData(sessionId, certData.certID, certData.certLABEL, hashToSign);
                        
                        signedContent = pdfManager.buildSignedPDF(digestOIDToUse, signature, hash);
                        new PDFManager(signedContent, null).isCorrectlySigned();
                    }
                    
                    dataSignedList.add(new Data(contentId, signedContent, signConfig));
                }
            
            } finally {
                smartCardAccessManager.closeSession(sessionId);
            }
        } finally {
            smartCardAccessManager.disconnectLibrary();
        }
        
        return this;
    }
    
    private CertificateData checkAlternativeLibraries(String pin, CertificateData certData, String digestOIDToUse) throws Exception {
        String errorMsgLibraryList = "";
        ArrayList<CertificateData> certDataList = new ArrayList<CertificateData>();
        certDataList.add(certData);
        certDataList.addAll(certData.alternativeCertificateList);
        for(CertificateData certDataToCheck : certDataList) {
            long sessionId = 0;
            errorMsgLibraryList += certDataToCheck.dll+"\n";
            try{
                long[] slotList = smartCardAccessManager.connectToLibrary(certDataToCheck.dll);
                if(!SignUtils.isContainedIntoArray(certDataToCheck.slot, slotList))
                    throw new Exception("Impossible to use the slot " + certDataToCheck.slot + " with the library " + certDataToCheck.dll);
                sessionId = smartCardAccessManager.login(certDataToCheck.slot, pin);
                
                byte[] dataTest = "test".getBytes();
                byte[] hashToSign = SignUtils.calculateHASH(digestOIDToUse, dataTest);
                hashToSign = CMSSignedDataWrapper.getDigestInfoToSign(digestOIDToUse, hashToSign);
                byte[] signature = smartCardAccessManager.signData(sessionId, certDataToCheck.certID, certDataToCheck.certLABEL, hashToSign);
                java.security.Signature sig = java.security.Signature.getInstance("SHA256WithRSA", "BC");
                sig.initVerify(certDataToCheck.cert.getPublicKey());
                sig.update(dataTest);
                if(sig.verify(signature))
                    return certDataToCheck;
            }catch(Exception ex) {ex.printStackTrace();} finally {
                smartCardAccessManager.closeSession(sessionId);
                smartCardAccessManager.disconnectLibrary();
            }
        }
        
        throw new Exception("Impossible to perform a valid signature with the following certificate and libraries\nCertificate: '" + certData.cert.getSubjectDN().getName() + "'\nLibraries:\n" + errorMsgLibraryList);
    }
    
    public SignEngine loadSmartCardCertificateList(boolean readAllCertificates){

        ArrayList<CertificateData> certList = new ArrayList<CertificateData>();
        
        for(String dll : dllList){
            String dllFullPath = SignUtils.getLibraryFullPath(dll);
            if(dllFullPath == null)
                continue;
            long[] slotList = null;
            try{
                slotList = smartCardAccessManager.connectToLibrary(dllFullPath);
            }catch(Exception ex){
                //ex.printStackTrace();
                smartCardAccessManager.disconnectLibrary();
                System.err.println(ex.getMessage());
                continue;
            }
            
            for(long slot : slotList){
                ArrayList<CertificateData> certInSlotList = null;
                try{
                    certInSlotList = smartCardAccessManager.getCertificateList(slot);
                }catch(Exception ex){
                    //ex.printStackTrace();
                    System.err.println(ex.getMessage());
                    continue;
                }
                
                for(CertificateData cert : certInSlotList){
                    cert.id = certList.size() + ": " + SignUtils.getIDFromSubject(cert.cert.getSubjectDN().getName());
                    cert.dll = dllFullPath;
                    cert.slot = slot;
                    int certIndex = certList.indexOf(cert);
                    if(certIndex == -1){
                        certList.add(cert);
                    } else {
                        CertificateData certOrig = certList.get(certIndex);
                        certOrig.alternativeCertificateList.add(cert);
                    }
                }
            }
            
            smartCardAccessManager.disconnectLibrary();
        }
        
        if(!readAllCertificates)
            certList = SignUtils.processCertificateList(certList);
        this.certificateList = certList;
        return this;
    }
}
