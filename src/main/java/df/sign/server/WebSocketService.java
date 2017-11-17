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
package df.sign.server;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonValue.ValueType;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

import df.sign.SignFactory;
import df.sign.SignUI;
import df.sign.SignUtils;
import df.sign.datastructure.Data;
import df.sign.datastructure.SignConfig;

@ServerEndpoint(value = "/sign")
public class WebSocketService {
    @OnMessage
    public String startSignProcess(String message, Session session) {
        try{
            JsonObject jsonObject = Json.createReader(new StringReader(message)).readObject();
            JsonArray dataToSignArray = jsonObject.getJsonArray("dataToSign");
            
            List<Data> dataToSignList = new ArrayList<Data>();

            for(int i=0; i<dataToSignArray.size();i++){
                if(dataToSignArray.get(i).getValueType()!=ValueType.OBJECT)
                    throw new Exception("Expected Json Object");
                String id = ((JsonObject)dataToSignArray.get(i)).getString("id");
                String contentB64 = ((JsonObject)dataToSignArray.get(i)).getString("contentB64");
                byte[] content = SignUtils.base64Decode(contentB64.getBytes("UTF-8"));
                SignConfig config = new SignConfig();
                JsonObject parameters = ((JsonObject)dataToSignArray.get(i)).getJsonObject("params");
                
                if(parameters != null){
                    config.signPdfAsP7m = parameters.getBoolean("signPdfAsP7m", false);
                    config.visibleSignature = parameters.getBoolean("visibleSignature", true);
                    config.pageNumToSign = parameters.getInt("pageNumToSign", -1);
                    config.signPosition = parameters.getString("signPosition", "left");
                }
                
                dataToSignList.add(new Data(id, content, config));
            }

            List<Data> dataSignedList = SignFactory.performSign(dataToSignList);
            
            JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();
            for(Data dataSigned : dataSignedList){
                String contentB64 = new String(SignUtils.base64Encode(dataSigned.data), "UTF-8");
                jsonArrayBuilder.add(Json.createObjectBuilder().add("id", dataSigned.id).add("contentB64", contentB64));
            }
            
            JsonObject ret = Json.createObjectBuilder().add("dataSigned", jsonArrayBuilder).build();
            String retS = ret.toString();
            
            return retS;
            
        }catch(Exception ex){
            ex.printStackTrace();
            SignUI.showErrorMessage(ex.getMessage());
            return "{\"error\" : \""+ex.getMessage().replace("\"", "\\\"").replace("\\", "\\\\")+"\"}";
        } finally {
            //SignFactory.getUniqueWebSocketServer().terminate();
        }
    }
}
