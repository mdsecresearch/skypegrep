/* pcapExtract - MDSec Consulting Ltd, 2013
 *
 * Shaun Colley & Dominic Chell, HackinTheBox Conf 2013
 *
 */

package pcapextract;
import edu.gatech.sjpcap.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class PcapExtract {

    private String pcapFile;
    private String pcapData = new String();
    /* default max number of packets to use from pcap file, can be increased for very large pcaps */
    private int numPackets = 60000000;
    
    long[] outDataTemp;
    long[] outData;
    long[] outTimestamps;
    long[] outTimestampsTemp;

    public void setPcapFile(String filePath)
    {
        pcapFile = filePath;
    }

    public String getPcapData()
    {
        return pcapData;
    }
    
    public void setNumPackets(int num)
    {
        numPackets = num;
    }

    public long[] getOutData() {
        return outData;
    }
    
    public long[] getOutTimestamps() {
        return outTimestamps;
    }
    
    public boolean parsePcap()
    {
        PcapParser pcapParser = new PcapParser();
        int noPackets = 0;
        int byteCounter = 0;
        
        if(pcapParser.openFile(pcapFile) < 0){
            System.err.println("Failed to open " + pcapFile + " - invalid pcap?");
            System.exit(1);
        }
                
        outDataTemp = new long[this.numPackets];
        outTimestampsTemp = new long[this.numPackets];
        
        Packet packet = pcapParser.getPacket();
        while (packet != Packet.EOF && noPackets < this.numPackets) {
            if (!(packet instanceof IPPacket)) {
                packet = pcapParser.getPacket();
                continue;
            }
            
            IPPacket ipPacket = (IPPacket) packet;
            
            if (ipPacket instanceof UDPPacket) {

                UDPPacket udpPacket = (UDPPacket) ipPacket;
                pcapData += udpPacket.data.length + " ";
                
                Date date = new Date(udpPacket.timestamp);
                DateFormat formatter = new SimpleDateFormat("HH:mm:ss:SS");
                String dateFormatted = formatter.format(date);
                
                byteCounter += udpPacket.data.length;
                outDataTemp[noPackets] = udpPacket.data.length;
                outTimestampsTemp[noPackets] = udpPacket.timestamp;
            }

            packet = pcapParser.getPacket();
            noPackets++;
        }
        
        outData = new long[noPackets];
        System.arraycopy(outDataTemp, 0, outData, 0, noPackets);
        
        outTimestamps = new long[noPackets];
        System.arraycopy(outTimestampsTemp, 0, outTimestamps, 0, noPackets);
        
        pcapParser.closeFile();
        
       return true;
    }
}
