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

public class PcapExtractTraining {

    private String pcapFile;
    private String pcapData = new String();
    /* default max number of packets to use from pcap file, can be increased for very large pcaps */
    private int numPackets = 60000000; 
    private int startOffset = 0;
    
    long[] xData = null;
    long[] yData = null;


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

    public void setStartOffset(int num) {
        startOffset = num;
    }
    
    public long[] getXData() {
        return xData;
    }
    
    public long[] getYData() {
        return yData;
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
                
        Packet discard = null;
        
        for(int offCtr = 0; offCtr < this.startOffset - 1; offCtr++) {
            discard = pcapParser.getPacket();
        }
    
        int smallPackets = 0;
        
        xData = new long[numPackets];
        yData = new long[numPackets];
        
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
                
                xData[noPackets] = udpPacket.timestamp;
                yData[noPackets] = udpPacket.data.length;
                
            }

            packet = pcapParser.getPacket();
            noPackets++;
        }
        
        pcapParser.closeFile();
        return true;
    }
}
