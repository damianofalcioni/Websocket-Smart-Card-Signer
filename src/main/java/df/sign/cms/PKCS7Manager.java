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
package df.sign.cms;

import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import df.sign.utils.X509Utils;

public class PKCS7Manager {

    public static boolean isPKCS7File(byte[] fileContent) {
        try {
            new CMSSignedData(fileContent);
            return true;
        } catch (Exception e) {}
        return false;
    }

    public static byte[] buildPDFPKCS7(String digestOID, X509Certificate cert, byte[] signature, byte[] hash, Date dateTime) throws Exception {
        return buildPKCS7(digestOID, null, cert, signature, hash, dateTime);
    }

    @SuppressWarnings("unchecked")
    public static byte[] buildPKCS7(String digestOID, byte[] data, X509Certificate cert, byte[] signature, byte[] hash, Date dateTime) throws Exception {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());

        CMSSignedDataWrapper cmsSignedDataWrapper = new CMSSignedDataWrapper();

        byte[] content = data;

        if (data != null && isPKCS7File(data)) { // Here I have to add all the already presents signatures
            CMSSignedData cmsSignedDataOLD = new CMSSignedData(data);
            cmsSignedDataWrapper.addSignerInformation(cmsSignedDataOLD.getSignerInfos());
            cmsSignedDataWrapper.addCert(cmsSignedDataOLD.getCertificates());
            cmsSignedDataWrapper.addCrl(cmsSignedDataOLD.getCRLs());
            content = extractData(data);
        }

        cmsSignedDataWrapper.addSignerInformation(digestOID, CMSSignedDataGenerator.ENCRYPTION_RSA, cert, signature, hash, dateTime);
        cmsSignedDataWrapper.addCert(cert.getEncoded());

        if (content != null)
            cmsSignedDataWrapper.setContent(content);
        else
            cmsSignedDataWrapper.setEncapsulate(false);

        CMSSignedData cmsSignedData = cmsSignedDataWrapper.buildCMSSignedData();

        return cmsSignedData.getEncoded();
    }

    public static boolean verifySignature(CMSSignedData cmsSignedData, X509Certificate cert) {
        try {
            if (Security.getProvider("BC") == null)
                Security.addProvider(new BouncyCastleProvider());

            Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
            X509CertificateHolder ch = new X509CertificateHolder(cert.getEncoded());
            for (SignerInformation si : signers)
                if (si.getSID().match(ch))
                    if (si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(ch)))
                        return true;
        } catch (Exception e) {}
        return false;
    }

    public static boolean verifySignatureOfUser(byte[] PKCS7Content, String userCF) {
        try {
            if (userCF == null || userCF.equals(""))
                throw new Exception("ERROR: userCF can not be null or empty");

            if (Security.getProvider("BC") == null)
                Security.addProvider(new BouncyCastleProvider());

            CMSSignedData cmsSignedData = new CMSSignedData(PKCS7Content);
            boolean findedCert = false;
            int invalidCerts = 0;
            Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
            for (SignerInformation si : signers) {
                @SuppressWarnings("unchecked")
                Collection<X509CertificateHolder> certList = cmsSignedData.getCertificates().getMatches(si.getSID());
                X509CertificateHolder cert = certList.iterator().next();

                if (cert.getSubject().toString().toLowerCase().contains(userCF.toLowerCase())) {
                    findedCert = true;
                    if (si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                        boolean certOK = true;
                        try {
                            X509Utils.checkAllOnCertificate(X509Utils.getX509Certificate(cert.getEncoded()));
                        } catch (Exception ex) {
                            ex.printStackTrace();
                            certOK = false;
                        }
                        if (certOK)
                            return true;
                        else
                            invalidCerts++;
                    } else
                        invalidCerts++;
                }
            }
            if (!findedCert)
                throw new Exception("ATTENTION: No certificate found in the PKCS7 data that contain the CF " + userCF + " in its subjectDN");
            if (invalidCerts != 0)
                throw new Exception("ATTENTION: N. " + invalidCerts + " certificates associated to the user " + userCF + " seems to be invalid. Please check them!");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    public static boolean verifyAllSignatures(byte[] PKCS7Content) {
        try {
            return verifyAllSignatures(new CMSSignedData(PKCS7Content));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean verifyAllSignatures(CMSSignedData cmsSignedData) {
        try {
            if (Security.getProvider("BC") == null)
                Security.addProvider(new BouncyCastleProvider());

            Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();

            for (SignerInformation si : signers) {
                @SuppressWarnings("unchecked")
                Collection<X509CertificateHolder> certList = cmsSignedData.getCertificates().getMatches(si.getSID());
                if (certList.size() == 0)
                    throw new Exception("ERROR: Impossible to find a Certificate using the Signer ID: " + si.getSID());

                X509CertificateHolder cert = certList.iterator().next(); // Take only the first certificate of the chain

                if (!si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)))
                    throw new Exception("ATTENTION: At least a signature is invalid!");

                boolean certOK = true;
                String msg = "";
                try {
                    X509Utils.checkAllOnCertificate(X509Utils.getX509Certificate(cert.getEncoded()));
                } catch (Exception ex) {
                    msg = ex.getMessage();
                    certOK = false;
                }
                if (!certOK)
                    throw new Exception("ATTENTION: The certificate is invalid:\n" + msg);
            }

            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    public static byte[] extractData(byte[] pkcs7Data) {
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(pkcs7Data);
            ByteArrayOutputStream bs = new ByteArrayOutputStream();
            cmsSignedData.getSignedContent().write(bs);
            return bs.toByteArray();
        } catch (Exception e) {}
        return new byte[0];
    }

    public static byte[] extractData(CMSSignedData cmsSignedData) {
        try {
            ByteArrayOutputStream bs = new ByteArrayOutputStream();
            cmsSignedData.getSignedContent().write(bs);
            return bs.toByteArray();
        } catch (Exception e) {}
        return new byte[0];
    }
}
