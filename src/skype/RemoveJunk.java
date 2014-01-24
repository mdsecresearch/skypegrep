/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package skype;

import pcapextract.PcapExtract;

/**
 *
 * @author shaun
 */
public class RemoveJunk {
    
    String inData;
    long[] testData;
    long[] cleanData;
    
    public long[] getCleanData() {
        return cleanData;
    }
    
    public RemoveJunk(PcapExtract pcapIn) {
        inData = pcapIn.getPcapData();
        
        /* convert this space-separated list of ints (String) to an array of
         * longs (long[]) so we can remove junk packets from it.
         */
        
        String[] splitData = inData.split(" ");
        testData = new long[splitData.length];
        for(int i = 0; i < testData.length; i++) {
            testData[i] = Integer.parseInt(splitData[i]);
            
        }
        
        System.out.println("converted string ints to long array");
        
    }
    
    public void clean() {
        
        long[] tempData = new long[testData.length];
        int j = 0;
        /* remove packets that are below 50 in length */
        for(int i = 0; i < testData.length; i++) {
            if(testData[i] <= 50) {
                /* not a speech packet, ignore */
                continue;
                        
            }
            
            else {
                tempData[j] = testData[i];
                j++;
            }
        } // end for
        
        cleanData = new long[j];
        System.arraycopy(tempData, 0, cleanData, 0, j);
    } // end clean()
    
}
