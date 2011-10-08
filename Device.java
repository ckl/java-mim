import java.io.*;
import java.util.Arrays;

import jpcap.*;

public class Device {
	BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
	private NetworkInterface[] devices;
	private int deviceNumber;
	private JpcapCaptor deviceCaptor;
	private byte[] ipAddr;
	private byte[] macAddr;
	
	public Device() {
		deviceNumber = 0;
		deviceCaptor = null;
		ipAddr = null;
		macAddr = null;
		retrieveNicDevices();
	}

   	public void retrieveNicDevices() {
   		devices = JpcapCaptor.getDeviceList();
   	}
    
    public void selectNicAndRetrieveIpAndMacAddr() {
    	selectNicDevice();
    	openNicDevice();
    	retrieveIpAddr();
    	retrieveMacAddr();
    }
    
    public void selectNicDevice() {
    	displayNicDevices();
    	promptForNicDeviceNumber();
    }
    
    private void displayNicDevices() {
    	for(int i = 0; i < devices.length; i++) {
    		System.out.println(i + ": " + devices[i].name + "(" + devices[i].description + ")");
    		for(NetworkInterfaceAddress a : devices[i].addresses)
    			System.out.println("Address: " + a.address);
    	}
    }
    
    private void promptForNicDeviceNumber() {
    	String nic = null;
    	
    	System.out.print("Enter NIC Device: ");
    	try {
    		nic = stdin.readLine();
    	}
    	catch(IOException e) {
    		displayCatchMessageAndExit(e);
    	}
    	
    	deviceNumber = Integer.parseInt(nic);
    }
    
    public void openNicDevice() {
    	try {
    		deviceCaptor = JpcapCaptor.openDevice(devices[deviceNumber], 65535, false, 20);
    	}
    	catch(IOException e) {
    		displayCatchMessageAndExit(e);
    	}
    }
    
    public void setCaptorFilter(String filter) {
    	try {
    		deviceCaptor.setFilter(filter, true);
    	}
    	catch(IOException e) {
    		displayCatchMessageAndExit(e);
    	}
    }
    
    public void retrieveMacAddr() {
    	macAddr = devices[deviceNumber].mac_address;
    }
    
    public void retrieveIpAddr() {
    	for(NetworkInterfaceAddress a : devices[deviceNumber].addresses)
    		ipAddr = a.address.getAddress();
    }
    
    public JpcapCaptor getDeviceCaptor() {
    	return deviceCaptor;
    }
    
    public byte[] getIpAddr() {
    	return ipAddr;
    }
    
    public byte[] getMacAddr() {
    	return macAddr;
    }
    
    public void displayIpAndMacAddr() {
		System.out.println(Arrays.toString(ipAddr));
		System.out.println(Arrays.toString(macAddr));
    }
    
    private void displayCatchMessageAndExit(IOException e) {
    	System.out.println(e.getMessage());
    	System.exit(1);
    }
    
}