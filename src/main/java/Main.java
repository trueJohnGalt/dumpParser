import io.pkts.Pcap;
import io.pkts.packet.IPPacket;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class Main {
    public static void main(String[] args) {

        ArrayList<Packet> listTCP = new ArrayList<>();
        ArrayList<Packet> listIP = new ArrayList<>();
        ArrayList<Packet> listSYNandACK = new ArrayList<>();
        ArrayList<Packet> listSYN = new ArrayList<>();
        ArrayList<Packet> listACK = new ArrayList<>();
        IPPacket packetExample;
        IPPacket packetSYNExample;
        try {
            Pcap pcap = Pcap.openStream("dump.pcap");
            pcap.loop((final Packet packet) -> {
                if(packet.hasProtocol(Protocol.TCP)) {
                    listTCP.add(packet);
                }
                return true;
            });
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }

        try {
            Pcap pcap = Pcap.openStream("dump.pcap");
            pcap.loop((final Packet packet) -> {
                if(packet.hasProtocol(Protocol.IPv4)) {
                    listIP.add(packet);
                }
                return true;
            });
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        ArrayList<Integer> portList = new ArrayList<>();

        try {

            for (Packet packet : listTCP) {
                TCPPacket temp = (TCPPacket) packet.getPacket(Protocol.TCP);
                portList.add(temp.getDestinationPort());
                if(temp.isSYN() && temp.isACK()){
                    listSYNandACK.add(temp);
                }
                if(temp.isACK()){
                    listACK.add(temp);
                }
                if(temp.isSYN()){
                    listSYN.add(temp);
                }
            }
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }

        Set<Integer> uniquePorts = new HashSet<>(portList);
        //Answers
        try {
            packetExample = (IPPacket) listIP.get(10).getPacket(Protocol.IPv4);
            packetSYNExample = (IPPacket) listSYN.get(5).getPacket(Protocol.IPv4);
            Boolean checkSYNflood = listSYNandACK.size() > listACK.size();
            System.out.println("1. Сканування порта відбувається з адреси: " + packetExample.getSourceIP());
            System.out.println("2. Хост, що був просканований має адресу: " + packetExample.getDestinationIP());
            System.out.println("3. Діапазон просканованих портів: " +
                    Collections.min(uniquePorts) + "-" + Collections.max(uniquePorts));
            System.out.println("4. SYN-flood: " + checkSYNflood.toString());
            System.out.println("5. Відправник SYN пакетів: " + packetSYNExample.getSourceIP());
            System.out.println("6. Отримувач SYN пакетів: " + packetSYNExample.getDestinationIP());
            System.out.println("7. Кількість SYN пакетів: " + listSYN.size());
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }
}
