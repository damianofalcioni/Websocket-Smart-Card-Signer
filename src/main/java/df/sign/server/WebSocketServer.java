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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import org.glassfish.tyrus.server.Server;

public class WebSocketServer extends Thread {

    public final static int defaultPort = 8765;
    private Server server = null;
    
    private int port = -1;
    private boolean isStarted = false;
    private boolean isTerminated = false;
    private boolean terminate = false;
    private final Object terminate_lock = new Object();
    private final Object isTerminated_lock = new Object();
    private final Object isStarted_lock = new Object();
    
    private ActionListener statusChangelistener = null;
    
    public WebSocketServer(int port){
        this.port = port;
        server = new Server("0.0.0.0", this.port, "/websockets", null, WebSocketService.class);
    }
    
    public void onStatusChanged(ActionListener listener){
        statusChangelistener = listener;
    }
    
    public boolean isStarted(){
        synchronized (isStarted_lock) {
            return isStarted;
        }
    }
    
    public boolean isTerminated(){
        synchronized (isTerminated_lock) {
            return isTerminated;
        }
    }
    
    public boolean isTerminating(){
        synchronized (terminate_lock) {
            return terminate;
        }
    }
    
    public int getPort(){
        return port;
    }

    @Override
    public void run() {
        isStarted = false;
        isTerminated = false;
        terminate = false;
        try {
            server.start();
            if(statusChangelistener!=null)
                statusChangelistener.actionPerformed(new ActionEvent(this, 0, "started"));
        } catch (Exception e) {
            e.printStackTrace();
            terminate = true;
        }
        
        synchronized (isStarted_lock) {
            isStarted = true;
            isStarted_lock.notifyAll();
        }
        
        synchronized (terminate_lock) {
            while(!terminate){
                try {
                    terminate_lock.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    break;
                }
            }
        }
        
        server.stop();
        if(statusChangelistener!=null)
            statusChangelistener.actionPerformed(new ActionEvent(this, 1, "terminated"));
        
        synchronized (isTerminated_lock) {
            isTerminated = true;
            isTerminated_lock.notifyAll();
        }
    }
    
    public void waitTermination(){
        synchronized (isTerminated_lock) {
            while(!isTerminated){
                try {
                    isTerminated_lock.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    break;
                }
            }
        }
    }
    
    public void waitStart(){
        synchronized (isStarted_lock) {
            while(!isStarted){
                try {
                    isStarted_lock.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    break;
                }
            }
        }
    }
    
    public void serverThreadStart(){
        this.start();
    }

    public void terminate(){
        terminate(0);
    }
    public void terminate(int afterSeconds) {
        if(afterSeconds!=0){
            try {
                sleep(afterSeconds*1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        synchronized (terminate_lock) {
            terminate = true;
            terminate_lock.notifyAll(); // Unblocks thread
        }
    }
}