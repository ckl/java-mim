/* A class with mostly static methods that makes it
 * convenient to craft packets with given parameters */

import jpcap.*;
import jpcap.packet.Packet;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;

public class PacketCrafter {
	public static void craftARPPacket(JpcapCaptor deviceCaptor, byte[] srcIP, byte[] srcMAC, byte[] dstIP, byte[] dstMAC) {		
		// Create the ARP Packet
		ARPPacket arp = new ARPPacket();
		arp.hardtype = ARPPacket.HARDTYPE_ETHER;
		arp.prototype = ARPPacket.PROTOTYPE_IP;
		arp.operation = ARPPacket.ARP_REQUEST;
		arp.hlen = 6;
		arp.plen = 4;
		arp.sender_hardaddr = srcMAC;
		arp.sender_protoaddr = srcIP;
		arp.target_hardaddr = dstMAC;
		arp.target_protoaddr = dstIP;
		
		// Create the Ethernet Packet
		EthernetPacket ether = new EthernetPacket();
		ether.frametype = EthernetPacket.ETHERTYPE_ARP;
		ether.src_mac = srcMAC;
		ether.dst_mac = dstMAC;
		arp.datalink = ether;
		
		// Send the packet
		JpcapSender sender = deviceCaptor.getJpcapSenderInstance();
		sender.sendPacket(arp);
}
    
    public static void forwardPacket(JpcapCaptor deviceCaptor, Packet packet, Device nic, Host target) {
    	EthernetPacket ether = new EthernetPacket();
    	ether.frametype = EthernetPacket.ETHERTYPE_IP;
    	ether.src_mac = nic.getMacAddr();
    	ether.dst_mac = target.getMacAddr();
    	
    	packet.datalink = ether;
    	
    	JpcapSender sender = deviceCaptor.getJpcapSenderInstance();
    	sender.sendPacket(packet);
    }
    
}