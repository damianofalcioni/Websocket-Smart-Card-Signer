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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

import df.sign.SignUtils;

public class CMSSignedDataWrapper {

    private ArrayList<SignerInfo> signerInfList = new ArrayList<SignerInfo>();
    private ArrayList<ASN1Encodable> certList = new ArrayList<ASN1Encodable>();
    private ArrayList<ASN1Encodable> crlList = new ArrayList<ASN1Encodable>();
    private CMSProcessable content;
    private boolean encapsulate = true;

    public void addSignerInformation(SignerInformation signerInf) {
        signerInfList.add(signerInf.toASN1Structure());
    }

    public void addSignerInformation(SignerInformationStore signerInfStore) {
        Collection<SignerInformation> SignerInformationList = signerInfStore.getSigners();
        if (SignerInformationList != null)
            for (SignerInformation si : SignerInformationList)
                addSignerInformation(si);
    }

    public void addSignerInformation(String digestOID, String encOID, X509Certificate cert, byte[] signature) throws Exception {
        addSignerInformation(digestOID, encOID, cert, signature, null, null);
    }

    public void addSignerInformation(String digestOID, String encOID, X509Certificate cert, byte[] signature, byte[] hash, Date dateTime) throws Exception {
        AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOID), DERNull.INSTANCE);
        AlgorithmIdentifier encAlgId = null;
        
        if (encOID.equals(CMSSignedDataGenerator.ENCRYPTION_DSA))
            encAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(encOID));
        else
            encAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(encOID), DERNull.INSTANCE);
        
        ASN1OctetString encDigest = new DEROctetString(signature);
        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getTBSCertificate());
        ASN1InputStream aIn = new ASN1InputStream(bIn);
        TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(aIn.readObject());
        IssuerAndSerialNumber encSid = new IssuerAndSerialNumber(tbs.getIssuer(), cert.getSerialNumber());
        aIn.close();
        
        ASN1Set signedAttributes = null;
        if (hash != null)
            signedAttributes = buildSignedAttributes(hash, dateTime, cert);
        
        SignerInfo signerInfo = new SignerInfo(new SignerIdentifier(encSid), digAlgId, signedAttributes, encAlgId, encDigest, null);
        signerInfList.add(signerInfo);
    }

    public void addCert(byte[] cert) {
        certList.add(Certificate.getInstance(cert));
    }

    public void addCert(Store<X509CertificateHolder> certStore) throws Exception {
        if (certStore == null)
            return;
        Collection<X509CertificateHolder> certStoreList = certStore.getMatches(null);
        for (X509CertificateHolder cert : certStoreList)
            addCert(cert.getEncoded());
    }

    public void addCrl(byte[] crl) {
        crlList.add(Certificate.getInstance(crl));
    }

    public void addCrl(Store<X509CRL> crlStore) throws Exception {
        if (crlStore == null)
            return;
        Collection<X509CRL> crlStoreList = crlStore.getMatches(null);
        for (X509CRL crl : crlStoreList)
            addCert(crl.getEncoded());
    }

    public void setContent(CMSProcessable content) {
        this.content = content;
    }

    public void setContent(byte[] content) {
        this.content = new CMSProcessableByteArray(content);
    }

    public void setEncapsulate(boolean encapsulate) {
        this.encapsulate = encapsulate;
    }

    private static ASN1Set buildSignedAttributes(byte[] hash, Date dateTime, X509Certificate cert) throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data)));
        if (dateTime != null)
            v.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(dateTime))));
        v.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hash))));

        // CADES support section
        ASN1EncodableVector aaV2 = new ASN1EncodableVector();
        AlgorithmIdentifier algoId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(CMSSignedDataGenerator.DIGEST_SHA256), null);
        aaV2.add(algoId);
        byte[] dig = SignUtils.calculateHASH(CMSSignedDataGenerator.DIGEST_SHA256, cert.getEncoded());
        aaV2.add(new DEROctetString(dig));
        Attribute cades = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(new DERSequence(new DERSequence(new DERSequence(aaV2)))));
        v.add(cades);

        ASN1Set signedAttributes = new DERSet(v);
        return signedAttributes;
    }

    public static byte[] getDataToSign(final byte[] hash, final Date dateTime, final X509Certificate cert) throws Exception {
        return buildSignedAttributes(hash, dateTime, cert).getEncoded(ASN1Encoding.DER);
    }

    public static byte[] getDigestInfoToSign(final String digestOID, final byte[] digestBytes) throws Exception {
        return new org.bouncycastle.asn1.x509.DigestInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOID), DERNull.INSTANCE), digestBytes).getEncoded(ASN1Encoding.DER);
    }

    public CMSSignedData buildCMSSignedData() throws Exception {

        ASN1EncodableVector signerInfVList = new ASN1EncodableVector();
        ASN1EncodableVector digestAlgVList = new ASN1EncodableVector();

        for (SignerInfo signerInfo : signerInfList) {
            signerInfVList.add(signerInfo);
            digestAlgVList.add(signerInfo.getDigestAlgorithm());
        }

        ASN1Set certificateSet = null;

        if (certList.size() != 0) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            for (ASN1Encodable cert : certList)
                v.add(cert);
            certificateSet = new DERSet(v);
        }

        ASN1Set crlSet = null;

        if (crlList.size() != 0) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            for (ASN1Encodable crl : crlList)
                v.add(crl);
            crlSet = new DERSet(v);
        }

        ASN1ObjectIdentifier contentTypeOID = new ASN1ObjectIdentifier(CMSSignedDataGenerator.DATA);
        ContentInfo encInfo = null;

        if (encapsulate) {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            content.write(bOut);
            ASN1OctetString octs = new BEROctetString(bOut.toByteArray());
            encInfo = new ContentInfo(contentTypeOID, octs);
        } else
            encInfo = new ContentInfo(contentTypeOID, null);

        SignedData signedData = new SignedData(new DERSet(digestAlgVList), encInfo, certificateSet, crlSet, new DERSet(signerInfVList));
        ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);

        return new CMSSignedData(content, contentInfo);
    }
}
