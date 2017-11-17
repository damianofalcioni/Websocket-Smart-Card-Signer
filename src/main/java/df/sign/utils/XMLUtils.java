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
import java.security.cert.X509Certificate;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class XMLUtils {
    
    public static boolean verifySignature(Document doc , X509Certificate cert) {
        try{
            if (doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength() == 0)
                throw new Exception("Cannot find Signature element");
    
            DOMValidateContext valContext = new DOMValidateContext(cert.getPublicKey(), doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0));
    
            XMLSignature signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(valContext);
    
            return signature.validate(valContext); 
        }catch(Exception e){e.printStackTrace();}
        return false;
    }
    
    public static Document getXmlDocFromString(String xml) throws Exception{
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes()));
    }
}
