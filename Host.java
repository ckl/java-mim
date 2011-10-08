import java.io.*;
import java.util.Arrays;
import java.net.*;
import java.net.InetAddress;

import jpcap.*;
import jpcap.packet.ARPPacket;

public class Host {
	BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
	byte[] ipAddr;
	byte[] macAddr;
	
	public Host() {
		ipAddr = null;
		macAddr = null;
	}
	
	public void promptForIpAddr() {
		try {
			readIpAddr();
		}
		catch(IOException e) {
    		displayCatchMessageAndExit(e);
    	}
	}
		
	private void readIpAddr() throws IOException {
		String ip = null;
		
		ip = stdin.readLine();
		parseIpAddrToByteArray(ip);
	}
	
	private void parseIpAddrToByteArray(String ip) {
		try {
			InetAddress a = InetAddress.getByName(ip);
			ipAddr = a.getAddress();
		}
		catch(UnknownHostException e) {
			displayCatchMessageAndExit(e);
		}
	}
	
	/* Retrieve the MAC address of the host by sending an ARP request to the
	 * broadcast address and waiting for a reply from the IP address of the host.
	 * A valid IP must be assigned before calling this method. */
	public void retrieveMacAddr(JpcapCaptor deviceCaptor, byte[] srcIP, byte[] srcMAC) {
		checkIfIpInitialized();
		
		byte[] broadcast = new byte[] {(byte)255, (byte)255, (byte)255, (byte)255, (byte)255, (byte)255 };
		PacketCrafter.craftARPPacket(deviceCaptor, srcIP, srcMAC, ipAddr, broadcast);
				
		while(true) {
			ARPPacket p = (ARPPacket) deviceCaptor.getPacket();
			if(Arrays.equals(p.sender_protoaddr, ipAddr)) {
				macAddr = p.sender_hardaddr;
				return;
			}
		}
	}
	
	/* Consider turning this into an exception */
	private void checkIfIpInitialized() {
		if(ipAddr == null) {
			System.out.println("Error: IP MUST be initialized before calling retrieveMacAddr()");
			System.exit(1);
		}
	}
	
	public byte[] getIpAddr() {
		return ipAddr;
	}
	
	public byte[] getMacAddr() {
		return macAddr;
	}
    
    private void displayCatchMessageAndExit(Exception e) {
    	System.out.println(e.getMessage());
    	System.exit(1);
    }
}
