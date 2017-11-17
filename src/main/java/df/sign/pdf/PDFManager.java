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
package df.sign.pdf;

import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.AcroFields.FieldPosition;

import df.sign.cms.PKCS7Manager;
import df.sign.utils.IOUtils;
import df.sign.utils.StringUtils;
import df.sign.utils.X509Utils;

import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfEncryptor;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.PdfWriter;

public class PDFManager {

    private PdfReader reader;
    private PdfSignatureAppearance sap;
    private ByteArrayOutputStream bout;
    private byte[] dataToSign;
    private int csize = 4000;
    private X509Certificate x509Certificate;
    private int numPages;
    private Date dateTime;
    private int contentsSize = csize;

    public PDFManager(byte[] pdfData, X509Certificate cert) throws Exception {
        reader = new PdfReader(pdfData);
        bout = new ByteArrayOutputStream();
        PdfStamper stp = PdfStamper.createSignature(reader, bout, '\0', null, true);
        numPages = reader.getNumberOfPages();
        x509Certificate = cert;
        sap = stp.getSignatureAppearance();
    }

    public void setVisibleSignature(int numPage) {
        setVisibleSignature(numPage, null);
    }

    public void setVisibleSignature(int numPage, String signPosition) {
        if (numPage <= 0)
            numPage = numPages;
        Rectangle posArea = null;
        if (signPosition != null && !signPosition.equals("")) {
            if (signPosition.toLowerCase().equals("left"))
                posArea = new Rectangle(110, 160, 170, 200);
            if (signPosition.toLowerCase().equals("right"))
                posArea = new Rectangle(440, 160, 500, 200);
        } else
            posArea = getFreeArea(numPage, reader);

        sap.setVisibleSignature(posArea, numPage, null);
    }

    public void setVisibleSignature(float llx, float lly, float urx, float ury, int numPage) {
        if (numPage <= 0)
            numPage = numPages;
        sap.setVisibleSignature(new Rectangle(llx, lly, urx, ury), numPage, null);
    }

    public void setDateTime(Date dateTime) {
        this.dateTime = dateTime;
    }

    @SuppressWarnings("deprecation")
    public void preClose() throws Exception {
        if (dateTime != null)
            sap.setSignDate(StringUtils.dateToCalendar(dateTime));

        sap.setAcro6Layers(false);
        sap.setCertificate(x509Certificate);
        //sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);

        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ETSI_CADES_DETACHED); // PdfName.ADBE_PKCS7_DETACHED
        if (dateTime != null)
            dic.setDate(new PdfDate(sap.getSignDate()));
        dic.setName(X509Utils.getCN(x509Certificate));
        dic.setCert(x509Certificate.getEncoded());
        sap.setCryptoDictionary(dic);

        /*
         * PdfDictionary dic = new PdfDictionary(); 
         * dic.put(PdfName.FT, PdfName.SIG); 
         * dic.put(PdfName.FILTER, PdfName.ADOBE_PPKMS);
         * dic.put(PdfName.SUBFILTER, PdfName.ETSI_CADES_DETACHED);
         * dic.put(PdfName.M, new PdfDate(sap.getSignDate()));
         * dic.put(PdfName.NAME, new PdfString(Utils.getCN(cert)));
         * sap.setCryptoDictionary(dic);
         */

        HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(csize * 2 + 2));
        sap.preClose(exc);

        dataToSign = IOUtils.toByteArray(sap.getRangeStream());
    }

    public static boolean isAPdf(byte[] pdfData) {
        if (pdfData.length < 4)
            return false;
        if (pdfData[0] == '%' && pdfData[1] == 'P' && pdfData[2] == 'D' && pdfData[3] == 'F')
            return true;
        return false;
    }

    public byte[] getDataToHashAndSign() {
        return dataToSign;
    }

    public byte[] buildSignedPDF(String digestOID, byte[] signature, byte[] hash) throws Exception {
        byte[] hashTmp = null;
        if (dateTime != null)
            hashTmp = hash;

        byte[] pkcs7enc = PKCS7Manager.buildPDFPKCS7(digestOID, x509Certificate, signature, hashTmp, dateTime);

        PdfDictionary dic = new PdfDictionary();
        PdfString contents = new PdfString(pkcs7enc).setHexWriting(true);

        contentsSize = contents.length();

        dic.put(PdfName.CONTENTS, contents);
        sap.close(dic);

        return bout.toByteArray();
    }

    public byte[] protectPDF(byte[] pdfContent) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PdfEncryptor.encrypt(new PdfReader(pdfContent), out, true, null, null, PdfWriter.ALLOW_COPY | PdfWriter.ALLOW_DEGRADED_PRINTING | PdfWriter.ALLOW_PRINTING | PdfWriter.ALLOW_SCREENREADERS);
            return out.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pdfContent;
    }

    public int getContentsSize() {
        return contentsSize;
    }

    public void setContentsSize(int size) {
        csize = size;
    }

    public boolean isSigned() {
        return reader.getAcroFields().getSignatureNames().size() != 0;
    }

    public boolean isCorrectlySigned() {

        try {
            if (reader.getAcroFields().getSignatureNames().size() == 0)
                throw new Exception("ATTENTION: The pdf don't contains signatures");

            if (Security.getProvider("BC") == null)
                Security.addProvider(new BouncyCastleProvider());

            ArrayList<String> signNameList = reader.getAcroFields().getSignatureNames();
            for (String signName : signNameList) {
                if (!reader.getAcroFields().verifySignature(signName).verify())
                    throw new Exception("ATTENTION: The pdf has been modified after at least a signature!");
                java.security.cert.Certificate[] certList = reader.getAcroFields().verifySignature(signName).getCertificates();
                if (certList.length == 0)
                    throw new Exception("ERROR: Impossible to find a Certificate using the Signer ID: " + signName);
                java.security.cert.Certificate cert = certList[0];
                X509Certificate x509Certificate = X509Utils.getX509Certificate(cert.getEncoded());
                try {
                    X509Utils.checkAllOnCertificate(x509Certificate);
                } catch (Exception ex) {
                    throw new Exception("ATTENTION: The certificate is invalid:\n" + ex.getMessage());
                }
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean isCorrectlySignedByUser(String userCF) {
        try {
            if (reader.getAcroFields().getSignatureNames().size() == 0)
                throw new Exception("ATTENTION: The pdf don't contains signatures");

            if (Security.getProvider("BC") == null)
                Security.addProvider(new BouncyCastleProvider());

            ArrayList<String> signNameList = reader.getAcroFields().getSignatureNames();
            ArrayList<String> signNameOkList = new ArrayList<String>();
            ArrayList<X509Certificate> userCertList = new ArrayList<X509Certificate>();
            for (String signName : signNameList) {
                java.security.cert.Certificate[] certList = reader.getAcroFields().verifySignature(signName).getCertificates();
                if (certList.length == 0)
                    throw new Exception("ERROR: Impossible to find a Certificate using the Signer ID: " + signName);
                java.security.cert.Certificate cert = certList[0];

                X509Certificate x509Certificate = X509Utils.getX509Certificate(cert.getEncoded());
                if (x509Certificate.getSubjectDN().getName().toLowerCase().contains(userCF.toLowerCase())) {
                    if (!userCertList.contains(x509Certificate))
                        userCertList.add(x509Certificate);
                    signNameOkList.add(signName);
                }
            }
            if (signNameOkList.size() == 0)
                throw new Exception("ATTENTION: No certificate found in the signed pdf that contain the CF " + userCF + " in its subjectDN");
            for (String signNameOk : signNameOkList)
                if (!reader.getAcroFields().verifySignature(signNameOk).verify())
                    throw new Exception("ATTENTION: The pdf has been modified after a signature of the user " + userCF);

            String msg = "";
            boolean certOK = false;
            for (X509Certificate cert : userCertList) {
                try {
                    X509Utils.checkAllOnCertificate(cert);
                    certOK = true;
                    break;
                } catch (Exception ex) {
                    msg += ex.getMessage();
                }
            }
            if (!certOK)
                throw new Exception("ATTENTION: No valid certificate found for the user " + userCF + ":\n" + msg);

            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private Rectangle getFreeArea(int pageNum, PdfReader reader) {

        Rectangle pageSize = reader.getPageSize(pageNum);
        //System.out.println("PAGE "+pageNum+" SIZE: " + pageSize.getLeft() + "-" + pageSize.getBottom() + "-" + pageSize.getRight() + "-" + pageSize.getTop());

        ArrayList<Rectangle> signatureList = new ArrayList<Rectangle>();
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> signNameList = fields.getSignatureNames();
        for (String sigName : signNameList) {
            List<FieldPosition> fieldPosList = fields.getFieldPositions(sigName);
            for (FieldPosition fieldPos : fieldPosList)
                if (fieldPos.page == pageNum)
                    signatureList.add(fieldPos.position);
        }

        //for(Rectangle sign: signatureList) System.out.println("PAGE "+pageNum+" SIGNATURE: " + sign.getLeft() + "-" + sign.getBottom() + "-" + sign.getRight() + "-" + sign.getTop());

        float llx = 50, lly = 50, urx = 110, ury = 90;
        Rectangle ret = new Rectangle(llx, lly, urx, ury);

        do {
            Rectangle overlapped = getOverlapped(ret, signatureList);
            if (overlapped == null)
                break;

            ret = new Rectangle(overlapped.getRight(), lly, overlapped.getRight() + (urx - llx), ury);
            if (!contains(pageSize, ret))
                ret = new Rectangle(overlapped.getLeft(), overlapped.getTop(), overlapped.getRight(), overlapped.getTop() + (ury - lly));
        } while (true);

        return ret;
    }

    private static Rectangle getOverlapped(Rectangle rect, ArrayList<Rectangle> rectList) {
        for (Rectangle rect2 : rectList)
            if (overlaps(rect, rect2))
                return rect2;
        return null;
    }

    private static boolean overlaps(Rectangle rect1, Rectangle rect2) {
        if (rect1.getLeft() >= rect2.getRight() || rect1.getRight() <= rect2.getLeft() || rect1.getTop() <= rect2.getBottom() || rect1.getBottom() >= rect2.getTop())
            return false;
        return true;
    }

    private static boolean contains(Rectangle rect1, Rectangle rect2) {
        return rect1.getLeft() <= rect2.getLeft() && rect1.getRight() >= rect2.getRight() && rect1.getBottom() <= rect2.getBottom() && rect1.getTop() >= rect2.getTop();
    }
}
