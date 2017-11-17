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
package df.sign.pkcs11;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class CertificateData {
    public String id;
    public String dll;
    public long slot;
    public byte[] certID;
    public byte[] certLABEL;
    public X509Certificate cert;
    public ArrayList<CertificateData> alternativeCertificateList = new ArrayList<CertificateData>();

    @Override
    public int hashCode() {
        return cert.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof CertificateData))
            return o == this;
        return ((CertificateData) o).cert.equals(this.cert);
    }
}