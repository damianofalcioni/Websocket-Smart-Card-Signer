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
import java.awt.Dimension;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
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
    
    public SignUI(SignEngine signEngine){
        this.signEngine = signEngine;
    }

    public CertificateData showCertificateDialog(){
        
        final Choice certificateComboBox = new Choice();
        final JOptionPane optionPane = new JOptionPane();
        optionPane.setMessageType(JOptionPane.PLAIN_MESSAGE);
        
        JPanel panel = new JPanel();
        
        JButton signButton = new JButton("Sign");
        signButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(isCertificateCorrect(certificateComboBox))
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
        
        JButton refreshCertificateButton = new JButton();
        refreshCertificateButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e) {
                updateComboBox(certificateComboBox);
            }
        });
        refreshCertificateButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("refresh.png")));  
        refreshCertificateButton.setBorderPainted(false);  
        refreshCertificateButton.setFocusPainted(true);  
        refreshCertificateButton.setContentAreaFilled(false);
        refreshCertificateButton.setPreferredSize(new java.awt.Dimension(20,20));
        
        panel.add(certificateComboBox);
        panel.add(refreshCertificateButton);
        
        updateComboBox(certificateComboBox);
        
        optionPane.setMessage(panel);
        optionPane.setOptions(new Object[] { signButton, terminateButton});
        
        SignUtils.playBeeps(1);
        
        JDialog dialog = optionPane.createDialog(null, "Certificate selection");
        dialog.setAlwaysOnTop(true);
        dialog.setVisible(true);
        
        int retval = (optionPane.getValue() instanceof Integer)?((Integer)optionPane.getValue()).intValue():-1;
        dialog.dispose();
        
        if(retval == JOptionPane.OK_OPTION){
            CertificateData certData = SignUtils.getCertificateDataByID((String)certificateComboBox.getSelectedItem(), signEngine.certificateList);
            return certData;
        }
        return null;
    }
    
    private void updateComboBox(Choice certificateComboBox){
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
            SignUtils.playBeeps(2);
        }
        else{
            if(certificateComboBox.getItemCount()==2){
                certificateComboBox.remove(0);
            }
            SignUtils.playBeeps(1);
        }
    }
    
    private boolean isCertificateCorrect(Choice certificateComboBox){
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
    /*
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
    */
    public static String askForPIN() {
        final JOptionPane optionPane = new JOptionPane();
        optionPane.setMessageType(JOptionPane.PLAIN_MESSAGE);
        
        JPanel panel = new JPanel();
        
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
        
        JLabel lbl = new JLabel("Insert the PIN for the selected certificate: ");
        panel.add(lbl);
        panel.add(txt);
        
        JButton okButton = new JButton("OK");
        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                optionPane.setValue(JOptionPane.OK_OPTION);
            }
        });
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                optionPane.setValue(JOptionPane.CLOSED_OPTION);
            }
        });
        
        optionPane.setMessage(panel);
        optionPane.setOptions(new Object[] { okButton, cancelButton});
        
        SignUtils.playBeeps(1);
        
        JDialog dialog = optionPane.createDialog(null, "PIN");
        dialog.setAlwaysOnTop(true);
        dialog.setVisible(true);
        
        int retval = (optionPane.getValue() instanceof Integer)?((Integer)optionPane.getValue()).intValue():-1;
        dialog.dispose();
        
        if(retval == JOptionPane.OK_OPTION){
            return new String(txt.getPassword());
        }
        return null;
    }
    
    private void showHelp(){
        String[] dllList = signEngine.dllList;
        
        final JOptionPane optionPane = new JOptionPane();
        
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
        JTextArea txtConflicts = new JTextArea();
        txtConflicts.setColumns(60);
        txtConflicts.setRows(3);
        txtConflicts.setEditable(false);
        JScrollPane txtConflictsScroll = new JScrollPane (txtConflicts, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        panel.add(new JLabel(" "));
        panel.add(new JLabel("JAR CONFLICTS: "));
        panel.add(new JLabel(" "));
        panel.add(txtConflictsScroll);

        String conflicts = "No JAR conflicts identified";
        String[] conflictJARList = SignUtils.checkJarConflicts();
        if(conflictJARList.length != 0){
            conflicts = "";
            for(String conflictJAR:conflictJARList)
                conflicts += "- " + conflictJAR + "\n";
        }
        txtConflicts.setText(conflicts);
        
        String[] tableColumnNames = {"LIBRARY NAME", "STATUS", "SMARTCARD TYPE"};
        Object[][] tableData = new Object[dllList.length][3];
        JTable table = new JTable(tableData, tableColumnNames);
        JScrollPane tableScroll = new JScrollPane (table, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        tableScroll.setPreferredSize(new Dimension(60, 200));
        panel.add(new JLabel(" "));
        panel.add(new JLabel("LIBRARIES STATUS: "));
        panel.add(new JLabel(" "));
        panel.add(tableScroll);
        
        for(int i=0; i<dllList.length;i++){
            tableData[i][0] = dllList[i];
            tableData[i][1] = (SignUtils.getLibraryFullPath(dllList[i])!=null)?"INSTALLED":"NOT INSTALLED";
            tableData[i][2] = (SignUtils.getCardTypeFromDLL(dllList[i])!="")?SignUtils.getCardTypeFromDLL(dllList[i]):"NOT MANAGED";
        }
        
        JTextArea txtSmartcardInfo = new JTextArea();
        txtSmartcardInfo.setColumns(60);
        txtSmartcardInfo.setRows(3);
        txtSmartcardInfo.setEditable(false);
        JScrollPane txtSmartcardInfoScroll = new JScrollPane (txtSmartcardInfo, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        panel.add(new JLabel(" "));
        panel.add(new JLabel("CONNECTED SMARTCARD INFOS: "));
        panel.add(new JLabel(" "));
        panel.add(txtSmartcardInfoScroll);
        
        String smartcardInfo = "";
        ArrayList<String> cardATRList = SignUtils.getConnectedCardATR();
        if(cardATRList.size()==0){
            smartcardInfo = "SMARTCARD NOT CONNECTED\n";
        }else{
            smartcardInfo = "CONNECTED SMARTCARDS:\n";
            for(String cardATR:cardATRList){
                String[] cardInfo = SignUtils.getCardInfo(cardATR);
                if(cardInfo == null)
                    smartcardInfo += "- UNKNOWN. ATR: " + cardATR + "\n";
                else{
                    smartcardInfo += "- " + cardInfo[0] + "\tPKCS11: ";
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
                        smartcardInfo += "NOT INSTALLED-> " + dllList[0] + " DOWNLOAD URL: " + urlDllInstaller + "\n";
                    else
                        smartcardInfo += "INSTALLED->" + correctLibrary + "\n";
                }
            }
        }
        
        txtSmartcardInfo.setText(smartcardInfo);
        
        JTextArea txtLog = new JTextArea();
        txtLog.setColumns(60);
        txtLog.setRows(10);
        txtLog.setEditable(false);
        JScrollPane txtLogScroll = new JScrollPane (txtLog, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        panel.add(new JLabel(" "));
        panel.add(new JLabel("LOGS: "));
        panel.add(new JLabel(" "));
        panel.add(txtLogScroll);
        try {
            txtLog.setText(new String(IOUtils.readFile(SignUtils.logFilePath)));
        } catch(Exception e) {}
        optionPane.setMessageType(JOptionPane.PLAIN_MESSAGE);
        optionPane.setMessage(panel);
        optionPane.setOptions(new Object[] {"OK"});
        
        JDialog dialog = optionPane.createDialog(null, "Diagnostic");
        dialog.setVisible(true);
        dialog.setAlwaysOnTop(true);
        
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
    
    public void createTrayIcon() throws Exception{
        if(!SystemTray.isSupported())
            throw new Exception("SystemTray is not supported");
        
        SignFactory.getUniqueWebSocketServer().waitStart();
        
        final PopupMenu popup = new PopupMenu();
        final TrayIcon trayIcon = new TrayIcon(new ImageIcon(SignUI.class.getResource((SignFactory.getUniqueWebSocketServer().isTerminating())?"smTrayR.png":"smTrayG.png")).getImage());
        trayIcon.setImageAutoSize(true);

        final SystemTray tray = SystemTray.getSystemTray();
        
        MenuItem aboutItem = new MenuItem("About");
        MenuItem statusItem = new MenuItem("Server Status");
        MenuItem restartItem = new MenuItem("Restart Server");
        MenuItem locallyItem = new MenuItem("Sign Locally");
        MenuItem checkItem = new MenuItem("Check Problems");
        MenuItem exitItem = new MenuItem("Exit");
        popup.add(aboutItem);
        popup.addSeparator();
        popup.add(locallyItem);
        popup.addSeparator();
        popup.add(statusItem);
        popup.addSeparator();
        popup.add(restartItem);
        popup.addSeparator();
        popup.add(checkItem);
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
                JOptionPane.showMessageDialog(null, "WEBSOCKET SMARTCARD SIGNER\n\nCreated by: Damiano Falcioni (damiano.falcioni@gmail.com)");
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
        
        checkItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                showHelp();
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
