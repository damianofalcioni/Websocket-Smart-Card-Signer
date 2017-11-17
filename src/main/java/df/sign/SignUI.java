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

import java.awt.Choice;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;

import df.sign.datastructure.Data;
import df.sign.pkcs11.CertificateData;
import df.sign.utils.IOUtils;
import df.sign.utils.X509Utils;

public class SignUI {

    public SignEngine signEngine = null;
    
    public boolean readAllCertificates = false;
    public String dnRestrictedSignatureName = "";
    
    private Choice certificateComboBox = null;
    private JButton signButton = null;
    private JButton helpButton = null;
    private JButton refreshCertificateButton = null;
    
    public SignUI(SignEngine signEngine){
        this.signEngine = signEngine;
    }

    public CertificateData showCertificateDialog(){
        
        final JOptionPane optionPane = new JOptionPane();
        optionPane.setMessageType(JOptionPane.PLAIN_MESSAGE);
        
        JPanel panel = new JPanel();
        
        signButton = new JButton("Sign");
        signButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(isCertificateCorrect())
                    optionPane.setValue(JOptionPane.OK_OPTION);
            }
        });
        
        JButton terminateButton = new JButton("Cancel");
        terminateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                optionPane.setValue(JOptionPane.CLOSED_OPTION);
            }
        });
        
        helpButton = new JButton();
        helpButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e) {
                showHelp();
            }
        });
        helpButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("alert.png")));  
        helpButton.setBorderPainted(false);  
        helpButton.setFocusPainted(false);  
        helpButton.setContentAreaFilled(false);
        helpButton.setPreferredSize(new java.awt.Dimension(20, 20));

        certificateComboBox = new Choice();
        
        refreshCertificateButton = new JButton();
        refreshCertificateButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e) {
                updateComboBox();
            }
        });
        refreshCertificateButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("refresh.png")));  
        refreshCertificateButton.setBorderPainted(false);  
        refreshCertificateButton.setFocusPainted(true);  
        refreshCertificateButton.setContentAreaFilled(false);
        refreshCertificateButton.setPreferredSize(new java.awt.Dimension(20,20));
        
        panel.add(certificateComboBox);
        panel.add(refreshCertificateButton);
        panel.add(helpButton);
        
        updateComboBox();
        
        optionPane.setMessage(panel);
        optionPane.setOptions(new Object[] { signButton, terminateButton});
        
        SignUtils.playBeeps(1);
        
        JDialog dialog = optionPane.createDialog(null, "Certificate selection");
        dialog.setVisible(true);
        
        int retval = (optionPane.getValue() instanceof Integer)?((Integer)optionPane.getValue()).intValue():-1;
        dialog.dispose();
        
        if(retval == JOptionPane.OK_OPTION){
            CertificateData certData = SignUtils.getCertificateDataByID((String)certificateComboBox.getSelectedItem(), signEngine.certificateList);
            return certData;
        }
        return null;
    }
    
    private void updateComboBox(){
        refreshCertificateButton.setEnabled(false);
        signButton.setEnabled(false);
        
        certificateComboBox.removeAll();
        certificateComboBox.addItem("Loading Certificates...");
        certificateComboBox.select(0);
       
        ArrayList<CertificateData> certList = new ArrayList<CertificateData>();
        try {
            certList = signEngine.loadSmartCardCertificateList(readAllCertificates).certificateList;
        } catch (Exception e) {
            e.printStackTrace();
            SignUtils.playBeeps(1);
            JOptionPane.showMessageDialog(null, "ERROR LOADING CERTIFICATES:\n"+e.getMessage(), "ERROR", JOptionPane.ERROR_MESSAGE);
        }
        
        certificateComboBox.removeAll();
        certificateComboBox.addItem("--Select Certificate--");
        for(int i=0;i<certList.size();i++)
            certificateComboBox.addItem(certList.get(i).id);
        
        if(certificateComboBox.getItemCount()==1){
            certificateComboBox.removeAll();
            certificateComboBox.addItem("--No Certificates Available!--");
            //helpButton.setVisible(true);
            SignUtils.playBeeps(2);
        }
        else{
            if(certificateComboBox.getItemCount()==2){
                certificateComboBox.remove(0);
            }
            signButton.setEnabled(true);
            SignUtils.playBeeps(1);
        }
        
        refreshCertificateButton.setEnabled(true);
    }
    
    
    
    private boolean isCertificateCorrect(){
        CertificateData certData = SignUtils.getCertificateDataByID((String)certificateComboBox.getSelectedItem(), signEngine.certificateList);
        
        if(certData == null){
            SignUtils.playBeeps(2);
            JOptionPane.showMessageDialog(null, "CERTIFICATE NOT SELECTED", "ERRORE", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        
        if(dnRestrictedSignatureName.length() != 0){
            String cfCert = X509Utils.getCFFromCertSubject(certData.cert.getSubjectDN().getName());
            if(!cfCert.equals(dnRestrictedSignatureName.toUpperCase()))
                if(!certData.cert.getSubjectDN().getName().contains(dnRestrictedSignatureName.toUpperCase())){
                    SignUtils.playBeeps(2);
                    JOptionPane.showMessageDialog(null, "SIGNATURE AVAILABLE ONLY FOR USER " + dnRestrictedSignatureName +"\nThe selected certificate is valid for user " + cfCert, "ERROR", JOptionPane.ERROR_MESSAGE);
                    return false;
            }
        }
        
        if(!X509Utils.checkValidity(certData.cert, null)){
            SignUtils.playBeeps(2);
            int ret = JOptionPane.showConfirmDialog(null, "THE CERTIFICATE IS EXPIRED\nPROCEEDS ANYWAY?", "WARNING", JOptionPane.YES_NO_OPTION);
            if(ret != JOptionPane.YES_OPTION)
                return false;
        }
        
        if(X509Utils.checkIsSelfSigned(certData.cert)){
            SignUtils.playBeeps(2);
            int ret = JOptionPane.showConfirmDialog(null, "THE CERTIFICATE IS SELF SIGNED\nPROCEEDS ANYWAY?", "WARNING", JOptionPane.YES_NO_OPTION);
            if(ret != JOptionPane.YES_OPTION)
                return false;
        }
        
        if(X509Utils.checkIsRevoked(certData.cert)){
            SignUtils.playBeeps(2);
            int ret = JOptionPane.showConfirmDialog(null, "THE CERTIFICATE IS REVOKED\nPROCEEDS ANYWAY?", "WARNING", JOptionPane.YES_NO_OPTION);
            if(ret != JOptionPane.YES_OPTION){
                return false;
            }
        }
        
        return true;
    }
    
    public void sign(CertificateData certData, String pin){
        if(signEngine.getNumDataToSign() == 0){
            SignUtils.playBeeps(2);
            JOptionPane.showMessageDialog(null, "NO DATA TO SIGN", "ERROR", JOptionPane.ERROR_MESSAGE);
            refreshCertificateButton.setEnabled(true);
            signButton.setEnabled(true);
            return;
        }
 
        try {
            signEngine.sign(certData, pin);
        } catch (Exception e) {
            e.printStackTrace();
            SignUtils.playBeeps(1);
            JOptionPane.showMessageDialog(null, "ERROR DURING THE SIGNING PROCESS:\n"+e.getMessage(), "ERROR", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    public static String askForPIN(){
        final JPasswordField txt = new JPasswordField(8);

        txt.addAncestorListener(new AncestorListener(){
            @Override
            public void ancestorAdded(AncestorEvent arg0) {
                arg0.getComponent().requestFocusInWindow();
            }
            @Override
            public void ancestorMoved(AncestorEvent arg0) {}
            @Override
            public void ancestorRemoved(AncestorEvent arg0) {}
        });
        
        JLabel lbl = new JLabel("INSERT THE SMARTCARD PIN");
        JPanel pan = new JPanel();
        pan.add(lbl);
        pan.add(txt);
        
        SignUtils.playBeeps(1);
        int retval = JOptionPane.showOptionDialog(null, pan, "PIN", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, null);        
        if(retval == JOptionPane.OK_OPTION) 
            return new String(txt.getPassword());
        return null;
    }
    
    private void showHelp(){
        String[] dllList = signEngine.dllList;
        
        final JOptionPane optionPane = new JOptionPane();
        
        JPanel panel = new JPanel();
        JTextArea textArea = new JTextArea();
        JScrollPane scroll = new JScrollPane (textArea, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        
        panel.add(scroll);
        
        textArea.setColumns(60);
        textArea.setRows(20);
        textArea.setEditable(false);
        
        String data = "";
        String[] conflictJARList = SignUtils.checkJarConflicts();
        if(conflictJARList.length != 0){
            data += "Conflicts:\n";
            for(String conflictJAR:conflictJARList)
                data += "- " + conflictJAR + "\n";
        }
        if(dllList.length == 0)
            data += "The list of PKCS11 libs to use is empty\n";
        boolean noPKCS11Found = true;
        for(String dllListToTestSplitted: dllList)
            if(SignUtils.getLibraryFullPath(dllListToTestSplitted) != ""){
                noPKCS11Found = false;
                break;
            }
        
        if(noPKCS11Found)
            data += "NO ONE OF THE MANAGED PKCS11 LIBRARIES IS PRESENT IN THE SYSTEM\n";
        else {
            data += "\n  NAME\t\t    STATUS\t\t  SMARTCARD TYPE\n";

            for(String dll: dllList){
                String dllFull = SignUtils.getLibraryFullPath(dll);
                String installed;
                if(dllFull != null)
                    installed = "INSTALLED";
                else 
                    installed = "NOT INSTALLED";
                    
                data += dll + "\t\t";
                String supportedCard = SignUtils.getCardTypeFromDLL(dll);
                if(supportedCard == "")
                    supportedCard = "NOT MANAGED";
                data += installed + "\t\t" + supportedCard + "\n";
            }
            data += "\n";
        }
        
        ArrayList<String> cardATRList = SignUtils.getConnectedCardATR();
        if(cardATRList.size()==0){
            data += "\nSMARTCARD NOT CONNECTED\n";
        }else{
            data += "\nCONNECTED SMARTCARDS:\n";
            for(String cardATR:cardATRList){
                String[] cardInfo = SignUtils.getCardInfo(cardATR);
                if(cardInfo == null)
                    data += "- UNKNOWN. ATR: " + cardATR + "\n";
                else{
                    data += "- " + cardInfo[0] + "\tPKCS11: ";
                    String[] cardInfoDllList = cardInfo[1].split("%");
                    String urlDllInstaller = cardInfo[3];
                    String correctLibrary = "";
                    for(String cardInfoDll : cardInfoDllList){
                        String dllFullPath = SignUtils.getLibraryFullPath(cardInfoDll);
                        if(dllFullPath != ""){
                            correctLibrary = dllFullPath;
                            break;
                        }
                    }
                    if(correctLibrary == "")
                        data += "NOT INSTALLED-> " + dllList[0] + " DOWNLOAD URL: " + urlDllInstaller + "\n";
                    else
                        data += "INSTALLED->" + correctLibrary + "\n";
                }
            }
        }
        
        textArea.setText(data);
        
        optionPane.setMessageType(JOptionPane.PLAIN_MESSAGE);
        optionPane.setMessage(panel);
        optionPane.setOptions(new Object[] {"OK"});
        
        JDialog dialog = optionPane.createDialog(null, "Diagnostic");
        dialog.setVisible(true);
        
        optionPane.getValue();
        dialog.dispose();
    }
    
    public static List<Data> showFileSelection() throws Exception{
        List<Data> ret = new ArrayList<Data>();
        
        JFileChooser jfc = new JFileChooser();
        jfc.setMultiSelectionEnabled(true);
        
        jfc.setDialogTitle("Choose the files to sign");
        SignUtils.playBeeps(1);
        if(jfc.showOpenDialog(null) != JFileChooser.APPROVE_OPTION)
            return null;
        
        File[] choosedFileList = jfc.getSelectedFiles();
        for(File file:choosedFileList){
            String id = file.getAbsolutePath();
            byte[] fileContent = IOUtils.readFile(file);
            ret.add(new Data(id, fileContent));
        }
        return ret;
    }
    
    public static void showFileSave(List<Data> dataSignedList) throws Exception{
        for(Data dataSigned : dataSignedList){
            JFileChooser jfc = new JFileChooser();
            jfc.setMultiSelectionEnabled(false);
            jfc.setSelectedFile(new File(dataSigned.id+(dataSigned.id.toLowerCase().endsWith(".pdf") || dataSigned.id.toLowerCase().endsWith(".p7m")?"":(dataSigned.config.saveAsPDF?".pdf":".p7m"))));
            jfc.setDialogTitle("Save file");
            SignUtils.playBeeps(1);
            if(jfc.showSaveDialog(null) != JFileChooser.APPROVE_OPTION)
                continue;
            String fileName = jfc.getSelectedFile().getAbsolutePath();
            if(new File(fileName).exists()){
                SignUtils.playBeeps(1);
                if(JOptionPane.showConfirmDialog(null, "Overwrite the file " + fileName + " ?", "WARNING", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION)
                    continue;
            }
            
            IOUtils.writeFile(dataSigned.data, fileName, false);
        }
    }
    
    public static void showErrorMessage(String message){
        SignUtils.playBeeps(2);
        JOptionPane.showMessageDialog(null, message, "ERROR", JOptionPane.ERROR_MESSAGE);
    }
    
    public static void createTrayIcon() throws Exception{
        if(!SystemTray.isSupported())
            throw new Exception("SystemTray is not supported");
        
        SignFactory.getUniqueWebSocketServer().waitStart();
        
        final PopupMenu popup = new PopupMenu();
        final TrayIcon trayIcon = new TrayIcon(new ImageIcon(SignUI.class.getResource((SignFactory.getUniqueWebSocketServer().isTerminating())?"smTrayR.png":"smTrayG.png")).getImage());
        trayIcon.setImageAutoSize(true);

        final SystemTray tray = SystemTray.getSystemTray();
        
        MenuItem aboutItem = new MenuItem("About");
        MenuItem statusItem = new MenuItem("Status");
        MenuItem restartItem = new MenuItem("Restart Server");
        MenuItem locallyItem = new MenuItem("Sign Locally");
        MenuItem exitItem = new MenuItem("Exit");
        popup.add(aboutItem);
        popup.addSeparator();
        popup.add(statusItem);
        popup.addSeparator();
        popup.add(locallyItem);
        popup.addSeparator();
        popup.add(restartItem);
        popup.addSeparator();
        popup.addSeparator();
        popup.add(exitItem);
        trayIcon.setPopupMenu(popup);
        
        tray.add(trayIcon);
        
        ActionListener statusAL = new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if(SignFactory.getUniqueWebSocketServer().isTerminated())
                    JOptionPane.showMessageDialog(null, "WebSocket Server status: TERMINATED");
                else if(SignFactory.getUniqueWebSocketServer().isTerminating())
                    JOptionPane.showMessageDialog(null, "WebSocket Server status: TERMINATING");
                else if(SignFactory.getUniqueWebSocketServer().isStarted())
                    JOptionPane.showMessageDialog(null, "WebSocket Server status: STARTED on port " + SignFactory.getUniqueWebSocketServer().getPort());
                else
                    JOptionPane.showMessageDialog(null, "WebSocket Server status: NOT STARTED");
            }
        };
        
        final ActionListener onServerStatusChanged = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(e.getID() == 0)
                    trayIcon.setImage(new ImageIcon(SignUI.class.getResource("smTrayG.png")).getImage());
                else if(e.getID() == 1)
                    trayIcon.setImage(new ImageIcon(SignUI.class.getResource("smTrayR.png")).getImage());
                else
                    JOptionPane.showMessageDialog(null, "Event " + e.getActionCommand() + " not recognized");
            }
        };
        
        SignFactory.getUniqueWebSocketServer().onStatusChanged(onServerStatusChanged);
        
        trayIcon.addActionListener(statusAL);
        
        aboutItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showMessageDialog(null, "SMARTCARD SIGNATURE WEBSOCKET SERVER\n\nCreated by: Damiano Falcioni (damiano.falcioni@gmail.com)");
            }
        });
        
        statusItem.addActionListener(statusAL);
        
        locallyItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                SignFactory.performSignLocally();
            }
        });
        
        restartItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                SignFactory.getNewWebSocketServer().serverThreadStart();
                SignFactory.getUniqueWebSocketServer().waitStart();
                SignFactory.getUniqueWebSocketServer().onStatusChanged(onServerStatusChanged);
                trayIcon.setImage(new ImageIcon(SignUI.class.getResource((SignFactory.getUniqueWebSocketServer().isTerminating())?"smTrayR.png":"smTrayG.png")).getImage());
            }
        });
        
        exitItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                tray.remove(trayIcon);
                System.exit(0);
            }
        });
    }
}
