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

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

public class StringUtils {
    
    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String hexString) {
        return DatatypeConverter.parseHexBinary(hexString);
    }
    
    public static Calendar dateToCalendar(Date date){ 
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        return cal;
    }
    
    public static Date stringToDate(String dateTime, String format) throws Exception{
        return new SimpleDateFormat(format).parse(dateTime);
    }
    
    public static String dateToString(Date dateTime, String format) throws Exception{
        return new SimpleDateFormat(format).format(dateTime);
    }
    
    public static String getCurrentTime(String format){
        return new java.text.SimpleDateFormat(format).format(java.util.Calendar.getInstance().getTime());
    }
    
    public static byte[] trim(byte[] data){
        int i;
        
        for(i=data.length-1;i>=0;i--)
            if(data[i]!=0x00)
                break;
        byte[] ret = new byte[i+1];
        
        System.arraycopy(data, 0, ret, 0, i+1);

        return ret;
    }
}
