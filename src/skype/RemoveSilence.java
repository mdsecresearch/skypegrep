package skype;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import pcapextract.PcapExtract;
import pcapextract.PcapExtractTraining;
import pcapextract.PlotPacketTrace;


public class RemoveSilence {

    long[] inData;
    long[] newData;
    long[] inTimestamps;
    long[] newTimestamps;
    
    /* constructor for removing silence from training data */
    public RemoveSilence(PcapExtractTraining inPcap) {
            inData = inPcap.getYData();
            inTimestamps = inPcap.getXData();
    }
    
    /* constructor for removing silence from test sequence data */
    public RemoveSilence(PcapExtract inPcap) {
        inData = inPcap.getOutData();
        inTimestamps = inPcap.getOutTimestamps(); /* in case we want to plot anything later */
    }
    
    public long[] getNewY() {
        return newData;
    }
    
    public long[] getNewX() {
        return newTimestamps;
    }
    
    /* this method takes all the y values, i.e. packet sizes, and removes everything that
     * appears to be silence. a new line character (\n) is added between each sequence. the result
     * is a string.
     */
    public int remove() {
        
        /* what do we consider silence or noise? we'll start with the simple assumption that anything 
         * under packet length 82 is silence.
         * 
         * however, when skype conversations are represented visually it's easy to see that
         * amongst these low length packets there are also spikes of around 85-110, which we
         * will also need to remove.
         */
        long[] tempNewData = new long[inData.length];
        long []tempNewTimestamps = new long[inTimestamps.length];
        
        int inSilencePhase = 0;
        int numSilencePackets = 0;
        int silencePhaseCounter = 0;
        
        int j = 0;
                
        for(int i = 0; i < inData.length; i++) {
            
            if(inData[i] <= 82) { /* may need to tweak this a bit */
                numSilencePackets++;
                if(numSilencePackets >= 20) // 20+ small packets? silence or noise phase
                    inSilencePhase = 1;
                
                continue;
            }
            
            /* we observe certain spikes between ~85-110 in silent phases as well,
             * perhaps some kind of noise.
             * (may need to tweak this range a bit)
             */
            if(inSilencePhase == 1 && inData[i] >= 85 && inData[i] <= 110) {
                numSilencePackets++;
                continue;
            }
            
            /* if we get here, a silent phase has just ended, so increment the
             * silence phase counter by 1. 
             * also need to denote the start of a new samples phase with a new
             * line character
             */
            if(inSilencePhase == 1) {
                silencePhaseCounter++;
                
                tempNewData[j] = 222;
                tempNewTimestamps[j] = inTimestamps[i];
                j++;
            }
                 
            tempNewData[j] = inData[i];
            tempNewTimestamps[j] = inTimestamps[i];
            inSilencePhase = 0;
            numSilencePackets = 0;
            j++;
           
        }
        
            
        newData = new long[j];
        newTimestamps = new long[j];
        
        System.arraycopy(tempNewData, 0, newData, 0, j);
        System.arraycopy(tempNewTimestamps, 0, newTimestamps, 0, j);
                
        /* how many silence phases did we remove? */
        return silencePhaseCounter;
        
    }
    
    public int removeFromTest() {
        
        /* what do we consider silence? we'll start with the simple assumption that anything under
         * packet length 82 is silence.
         * 
         * however, when skype conversations are represented visually it's easy to see that
         * amongst these low length packets there are also spikes of around 85-110, which we
         * will also need to remove.
         */
        long[] tempNewData = new long[inData.length];
        long []tempNewTimestamps = new long[inTimestamps.length];
        
        int inSilencePhase = 0;
        int numSilencePackets = 0;
        int silencePhaseCounter = 0;
        
        int j = 0;
        
        System.out.println("removing silence from sequence of " + inData.length + " packet sizes");
        
        for(int i = 0; i < inData.length; i++) {
            
            if(inData[i] <= 82) { /* may need to tweak this a bit */
                numSilencePackets++;
                if(numSilencePackets >= 20) // 10+ small packets? silence phase
                    inSilencePhase = 1;
                
                continue;
            }
            
            /* we observe certain spikes between ~95-105 in silent phases as well 
             * may need to tweak this range a bit
             */
            if(inSilencePhase == 1 && inData[i] >= 85 && inData[i] <= 110) {
                numSilencePackets++;
                continue;
            }
            
            /* if we get here, a silent phase has just ended, so increment the
             * silence phase counter by 1. 
             * also need to denote the start of a new samples phase with a new
             * line character
             */
            if(inSilencePhase == 1) {
                silencePhaseCounter++;
                
                tempNewData[j] = 222;
                tempNewTimestamps[j] = inTimestamps[i];
                j++;
            }
                 
            tempNewData[j] = inData[i];
            tempNewTimestamps[j] = inTimestamps[i];
            inSilencePhase = 0;
            numSilencePackets = 0;
            j++;
           
        }
        
            
        newData = new long[j];
        newTimestamps = new long[j];
        
        System.arraycopy(tempNewData, 0, newData, 0, j);
        System.arraycopy(tempNewTimestamps, 0, newTimestamps, 0, j);
                
        /* how many silence phases did we remove? */
        return silencePhaseCounter;
        
    }   
}
