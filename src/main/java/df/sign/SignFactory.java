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

import java.util.List;

import df.sign.datastructure.Data;
import df.sign.pkcs11.CertificateData;
import df.sign.pkcs11.SmartCardAccessManagerFactory;
import df.sign.pkcs11.SmartCardAccessManagerFactory.PKCS11AccessMethod;
import df.sign.server.WebSocketServer;

public class SignFactory {

    public static PKCS11AccessMethod pkcs11AccessMethod = SmartCardAccessManagerFactory.PKCS11AccessMethod.JNA;
    
    private static SignEngine signEngine = null;
    private static SignUI signUI = null;
    private static WebSocketServer webSocketServer = null;
    
    public static SignUI getUniqueUI() throws Exception{
        if(signUI == null)
            signUI = new SignUI(getUniqueEngine());
        return signUI;
    }
    
    public static SignEngine getUniqueEngine() throws Exception{
        if(signEngine == null)
            signEngine = new SignEngine(SmartCardAccessManagerFactory.getSmartCardAccessManager(pkcs11AccessMethod), SignUtils.standardDllList);
        return signEngine;
    }
    
    public static WebSocketServer getUniqueWebSocketServer(){
        if(webSocketServer == null)
            webSocketServer = new WebSocketServer(WebSocketServer.defaultPort);
        return webSocketServer;
    }
    
    public static WebSocketServer getNewWebSocketServer(){
        if(webSocketServer != null){
            webSocketServer.terminate();
            webSocketServer.waitTermination();
            webSocketServer = null;
        }
        webSocketServer = new WebSocketServer(WebSocketServer.defaultPort);
        return webSocketServer;
    }
    
    public static List<Data> performSign(List<Data> dataToSignList) throws Exception{
        SignFactory.getUniqueEngine().cleanDataToSign().loadDataToSign(dataToSignList);
        SignUI signUi = SignFactory.getUniqueUI();
        CertificateData certificateData = signUi.showCertificateDialog();
        if(certificateData == null)
            throw new Exception("Process aborted");
        String pin = SignUI.askForPIN();
        if(pin == null)
            throw new Exception("Process aborted");
        signUi.sign(certificateData, pin);
        List<Data> signedDataList = SignFactory.getUniqueEngine().getSignedData();           
        return signedDataList;
    }
    
    public static void performSignLocally(){
        try {
            List<Data> dataToSignList = SignUI.showFileSelection();
            if(dataToSignList == null)
                throw new Exception("Process aborted");
            List<Data> dataSignedList = SignFactory.performSign(dataToSignList);
            SignUI.showFileSave(dataSignedList);
        } catch (Exception ex) {
            ex.printStackTrace();
            SignUI.showErrorMessage(ex.getMessage());
        }
    }
}
