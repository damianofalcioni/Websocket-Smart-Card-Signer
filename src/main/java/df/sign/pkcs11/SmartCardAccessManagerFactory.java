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

import df.sign.pkcs11.impl.iaik.SmartCardAccessIaikImpl;
import df.sign.pkcs11.impl.jna.SmartCardAccessJnaImpl;

public class SmartCardAccessManagerFactory {
    public static enum PKCS11AccessMethod {
        JNA,
        IAIK
    };
    private static SmartCardAccessI smartCardAccessManager_jna = null;
    private static SmartCardAccessI smartCardAccessManager_iaik = null;

    public static SmartCardAccessI getSmartCardAccessManager(PKCS11AccessMethod method) throws Exception {
        if (method == PKCS11AccessMethod.JNA) {
            if (smartCardAccessManager_jna == null)
                smartCardAccessManager_jna = new SmartCardAccessJnaImpl();
            return smartCardAccessManager_jna;
        }
        
        if (method == PKCS11AccessMethod.IAIK) {
            if (smartCardAccessManager_iaik == null)
                smartCardAccessManager_iaik = new SmartCardAccessIaikImpl();
            return smartCardAccessManager_iaik;
        }
        
        throw new Exception("The provided PKCS11 Access Method is not available");
    }
}
