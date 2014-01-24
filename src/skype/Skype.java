/* skypegrep - MDSec Consulting Ltd, 2013
 * 
 * Shaun Colley & Dominic Chell, HackinTheBox Conf 2013
 * 
 * proof-of-concept Profile Hidden Markov Model based attacks against encrypted 
 * VoIP streams.
 */
package skype;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import org.biojava.bio.Annotation;
import org.biojava.bio.BioException;
import org.biojava.bio.dist.DistributionFactory;
import org.biojava.bio.dp.BaumWelchTrainer;
import org.biojava.bio.dp.DP;
import org.biojava.bio.dp.DPFactory;
import org.biojava.bio.dp.IllegalTransitionException;
import org.biojava.bio.dp.ModelTrainer;
import org.biojava.bio.dp.ProfileHMM;
import org.biojava.bio.dp.ScoreType;
import org.biojava.bio.dp.SimpleModelTrainer;
import org.biojava.bio.dp.StatePath;
import org.biojava.bio.symbol.IllegalAlphabetException;
import org.biojava.bio.symbol.IllegalSymbolException;
import org.biojava.bio.symbol.SymbolList;
import org.biojava.bio.dp.StoppingCriteria;
import org.biojava.bio.dp.TrainingAlgorithm;
import org.biojava.bio.SimpleAnnotation;
import org.biojava.bio.seq.Sequence;
import org.biojava.bio.seq.db.HashSequenceDB;
import org.biojava.bio.seq.db.IllegalIDException;
import org.biojava.bio.seq.db.SequenceDB;
import org.biojava.bio.seq.impl.SimpleSequenceFactory;
import org.biojava.bio.symbol.AlphabetManager;
import org.biojava.bio.symbol.FiniteAlphabet;
import org.biojava.bio.symbol.IllegalSymbolException;
import org.biojava.bio.symbol.SimpleAlphabet;
import org.biojava.bio.symbol.SimpleSymbolList;
import org.biojava.bio.symbol.Symbol;
import org.biojava.bio.symbol.SymbolList;
import org.biojava.utils.ChangeVetoException;

import pcapextract.PcapExtract;
import pcapextract.PcapExtractTraining;
import pcapextract.PlotPacketTrace;

/**
 *
 * @author shaun
 */
public class Skype {

    static HashMap<String, Symbol> symbolMap = new HashMap<String, Symbol>();
    static ArrayList<ArrayList<Symbol>> trainingSymbols = new ArrayList<ArrayList<Symbol>>();
    static FiniteAlphabet alphabet = null;
    static SequenceDB finalTrainingSet = null;
    static DP dp = null;
    static ProfileHMM hmm = null;

    
    public static void main(String[] args) throws IllegalSymbolException, IllegalArgumentException, IllegalAlphabetException, InterruptedException, FileNotFoundException, IOException, ClassNotFoundException, BioException {

        System.out.println("");
        
        int extractTraining = 0;
        int plotTraining = 0;
        int averageSequenceLen = 0;
        double scoreThreshold = 0.0;

        PcapExtract pe = null;

        String[] testStrings = null;


        if (args.length >= 1) {
            if (args[0].equals("train") && args.length < 4) {
                System.out.println("voipgrep train [training.pcap] [test.pcap] [scoreThreshold]");
                System.exit(1);
            }

            else if (args[0].equals("train") && args.length >= 4) {
                extractTraining = 1;
            } 
            
            else if (args[0].equals("plot") && args.length < 3) {
                System.out.println("voipgrep plot [packets.pcap] [startOffset] [numPackets]");
                System.exit(1);
            }
            
            else if (args[0].equals("plot") && args.length >= 4) {
                plotTraining = 1;
            } 

        } else {
            System.out.println("*** standard usage:");
            System.out.println("voipgrep train [training.pcap] [test.pcap] [scoreThreshold]");
            System.out.println("");
            System.out.println("*** visually plot pkt sequences:");
            System.out.println("voipgrep plot [packets.pcap] [startOffset] [numPackets]");   
            System.exit(1);
        }


        RemoveSilence removeSilence = null;

        /* if we're extracting training data, we're just parsing our big pcap file */
        if (extractTraining == 1) {
            
            scoreThreshold = Double.parseDouble(args[3]);
            
            System.out.println("*** parsing training data pcap file");

            /* make new training pcap object */
            PcapExtractTraining extract = new PcapExtractTraining();

            /* set the file */
            extract.setPcapFile(args[1]);

            /* at which packet offset into the pcap file does the data start
             * at?
             */
            //extract.setStartOffset(Integer.parseInt(args[2]));
            //extract.setNumPackets(Integer.parseInt(args[3]));

            extract.parsePcap();

            /* create an object to remove silence from the packet sequences */
            removeSilence = new RemoveSilence(extract);

            System.out.println("*** removing silence & noise from training data");

            int numSilentPhasesRemoved = removeSilence.remove();

            System.out.println("*** number of silent & noisy phases removed: " + numSilentPhasesRemoved);

        } else if (plotTraining == 1) {
            System.out.println("*** extracting training data from pcap file");

            /* make new training pcap object */
            PcapExtractTraining extract = new PcapExtractTraining();

            /* set the file */
            extract.setPcapFile(args[1]);

            /* at which packet offset into the pcap file does the data start
             * at ?
             */
            extract.setStartOffset(Integer.parseInt(args[2]));
            extract.setNumPackets(Integer.parseInt(args[3]));

            extract.parsePcap();

            /* create an object to remove silence from the packet sequences */
            removeSilence = new RemoveSilence(extract);

            System.out.println("*** removing silence");

            int numSilentPhasesRemoved = removeSilence.remove();

            System.out.println("*** number of silent phases removed: " + numSilentPhasesRemoved);

            PlotPacketTrace myPlot = new PlotPacketTrace();

            myPlot.setX(removeSilence.getNewX());
            myPlot.setY(removeSilence.getNewY());
            myPlot.doPlot();

            Thread.sleep(100000);
            System.exit(1);

        } 

        pe = new PcapExtract();

        pe.setPcapFile(args[2]);

        if (pe.parsePcap()) {
            //System.out.println("parsed pcap test sequence from" + args[2]);
        }

        String testSeq = null;

        ArrayList<Symbol> symbolList = new ArrayList<Symbol>();

        ArrayList<String> trainingData = new ArrayList<String>();

        /* change all the int 222's in our long[] to '\n's */
        long[] trainingArray = removeSilence.getNewY();
        int replaceCount = 1;
        String bigTrainingString = null;

        /* turn the long[] of packet lengths into String of numbers separated by
         * whitespaces, with a new line (\n) between each training sequence so
         * that BufferedReader's readLine knows where each sequence begins and
         * ends. 222 was the dummy value we used in RemoveSilence to denote end
         * of a speech phase.
         */
        String trainingStringTemp = Arrays.toString(trainingArray).replace(", ", " ");
        String trainingStringTemp2 = trainingStringTemp.substring(1, trainingStringTemp.length() - 1);
        String trainingString = trainingStringTemp2.replace(" 222", "\n");

        InputStream is = new ByteArrayInputStream(trainingString.getBytes());

        BufferedReader reader;
        try {
            int lineCounter = 1;

            reader = new BufferedReader(new InputStreamReader(is));
            String data = null;
            while ((data = reader.readLine()) != null) {

                String[] pktSizes = data.split(" ");

                /* not likely to be a phrase that anyone
                 * is trying recognise due its short length, possibly noise. don't use this
                 * as training data */
                if (pktSizes.length < 100) {
                    continue;
                }

                /* XXX: this removes preceding whitespace, if there is one there.
                 * prevents an integer parse error later. */
                if (data.startsWith(" ")) {
                    data = data.substring(1);
                }

                trainingData.add(data);
                lineCounter++;
            }

            reader.close();
        } catch (Exception e) {
            System.out.println("exception caught parsing training data");
        }


        int numberOfPacketSizes = 0;
        int[] uniqueTracker = new int[500];
        int alphabetTracker = 0;
        for (int n = 0; n < uniqueTracker.length; n++) {
            uniqueTracker[n] = 0;
        }

        for (String trainingLine : trainingData) {

            String packetLens[] = trainingLine.split(" "); // whitespace

            numberOfPacketSizes += packetLens.length;

            for (String thisPacketLen : packetLens) {
                Integer size = Integer.parseInt(thisPacketLen);

                /* if this is the first occurance of thisPacketLen, increment
                 * alphabet count
                 */
                int index = Integer.parseInt(thisPacketLen);
                if (uniqueTracker[index] == 0) {
                    uniqueTracker[index] = 1;
                    alphabetTracker++;
                }

                Symbol psize = new PacketSizeSymbol(size, Annotation.EMPTY_ANNOTATION);
                if (symbolMap.containsKey(size.toString())) {
                    psize = symbolMap.get(size.toString());
                } else {
                    symbolMap.put(size.toString(), psize);
                }

                symbolList.add(psize);
            }

            trainingSymbols.add(symbolList);
        }

        averageSequenceLen = numberOfPacketSizes / trainingData.size();

        /* trainingSymbols now has all of our training packet sizes */
        System.out.println("*** parsed training data file (" + args[1] + ") successfully.");
        System.out.println("*** number of training sets: " + trainingData.size() + ". average training sequence length: " + averageSequenceLen);

        Set symbolSet = new HashSet<Symbol>();

        for (Symbol temp : symbolMap.values()) {
            symbolSet.add(temp);
        }

        alphabet = new SimpleAlphabet(symbolSet, "PacketSizeAlphabet");

        AlphabetManager.registerAlphabet("PacketSizeAlphabet", alphabet);
        finalTrainingSet = new HashSequenceDB();
        SimpleSequenceFactory factory = new SimpleSequenceFactory();

        /* turn our training sets into symbols that BioJava can understand */
        for (ArrayList<Symbol> mySymbolList : trainingSymbols) {

            try {
                SimpleSymbolList ssl = new SimpleSymbolList(alphabet, mySymbolList);
                Sequence tempSeq = factory.createSequence(ssl, "", ssl.seqString(), new SimpleAnnotation());

                finalTrainingSet.addSequence(tempSeq);

            } catch (Exception e) {
                System.out.println("error adding training sequences to finalTrainingSet");
            }
        }

        /* the test sequence.. */
        testSeq = pe.getPcapData();

        /* remove probable silence phases from test data */
        RemoveSilence cleanTestSeq = new RemoveSilence(pe);
        cleanTestSeq.remove();

        /* we now have all our test sequences available via cleanTestSeq.getNewY()
         * let's parse out the 222's and get ourselves a String[] with all ourselves
         * sequences to test against the PHMM
         */
        long[] cleanData = cleanTestSeq.getNewY();

        String testingStringTemp = Arrays.toString(cleanData).replace(", ", " ");
        String testingStringTemp2 = testingStringTemp.substring(1, testingStringTemp.length() - 1);
        String testingStringTemp3 = testingStringTemp2.replace(" 222", "\n");

        testStrings = testingStringTemp3.split("\n");
        
        /* turn cleaned data into a String of ints separated by whitespaces */
        String temp1 = Arrays.toString(cleanData).replace(", ", " ");
        testSeq = temp1.substring(1, temp1.length()-1);

        System.out.println("*** alphabet size: " + alphabetTracker);
        System.out.println("");

        try {
            hmm = new ProfileHMM(alphabet,
                    alphabetTracker,
                    DistributionFactory.DEFAULT,
                    DistributionFactory.DEFAULT,
                    "SkypeProfileHMM");

            dp = DPFactory.DEFAULT.createDP(hmm);

            ModelTrainer mt = new SimpleModelTrainer();
            mt.registerModel(hmm);
            mt.setNullModelWeight(1.0);
            mt.train();
        } catch (Exception e) {
            System.out.println("error creating initial profile HMM");
            System.exit(1);
        }

        BaumWelchTrainer bwt = new BaumWelchTrainer(dp);

        StoppingCriteria stopper = new StoppingCriteria() {
            public boolean isTrainingComplete(TrainingAlgorithm ta) {
                return (ta.getCycle() > 20);
            }
        };

        System.out.println("*** training Profile HMM");
        /*
         * optimize the dp matrix to reflect the training set in db using a null model
         * weight of 1.0 and the Stopping criteria defined above.
         */
        try {
            bwt.train(finalTrainingSet, 1.0, stopper);
        } catch (Exception e) {
            System.out.println("error training profile HMM with training data");
        }

        System.out.println("*** profile HMM trained..");
        
        /* XXX: just counting how many test strings we have.
         */
        int testSeqCounter = 0;

        testSeqCounter = 0;
        for (String testSequence : testStrings) {
            if (testSequence.startsWith(" ")) {
                testSequence = testSequence.substring(1);
            }
            String testLens[] = testSequence.split(" ");

            /* too short, could be noise or something. if it was actual speech we're going to 
             * have bad luck in detecting very short phrases anyway.
             */
            if (testLens.length < 100) {
                continue;
            }

            testSeqCounter++;

        }

        System.out.println("");
        System.out.println("*** parsing test sequence(s) pcap file..");
        System.out.println("");
        
        System.out.println("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-");

        int result;
        result = doViterbi(testStrings, averageSequenceLen, scoreThreshold);

        /* now setup a loop to take a filename of a test pcap and do viterbi on
         * that sequence vs. the profile HMM
         */

        InputStreamReader isr = new InputStreamReader(System.in);
        BufferedReader StdinReader = new BufferedReader(isr);
        String filename = null;

        while ((filename = StdinReader.readLine()) != null) {
            
            System.out.println("");
            System.out.println("*** parsing test sequence(s) pcap file..");
            System.out.println("");
            System.out.println("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-");


            PcapExtract extract = new PcapExtract();

            /* read in the filename, and set it in the object */
            extract.setPcapFile(filename);

            /* at which packet offset into the pcap file does the data start
             * at ?
             */
            // extract.setStartOffset(Integer.parseInt(args[2]));
            //extract.setNumPackets(Integer.parseInt(args[5]));

            extract.parsePcap();

            /* create an object to remove silence from the packet sequences */
            RemoveSilence deserializeRemoveSilence = new RemoveSilence(extract);

            int numSilentPhasesRemoved = deserializeRemoveSilence.remove();

            long[] deserializeCleanData = deserializeRemoveSilence.getNewY();

            testingStringTemp = Arrays.toString(deserializeCleanData).replace(", ", " ");
            testingStringTemp2 = testingStringTemp.substring(1, testingStringTemp.length() - 1);
            testingStringTemp3 = testingStringTemp2.replace(" 222", "\n");

            testStrings = testingStringTemp3.split("\n");
            
            extract = null; /* don't need this anymore */
            int ret = doViterbi(testStrings, averageSequenceLen, scoreThreshold);
        }


    }

    static int doViterbi(String[] testStrings, int averageSequenceLen, double scoreThreshold) throws IllegalSymbolException {

        int matches = 0;
        int numSequences = 0;
        
        for (String testSequence : testStrings) {
            if (testSequence.startsWith(" ")) {
                testSequence = testSequence.substring(1);
            }
            String testLens[] = testSequence.split(" ");
            
            /* too short, could be noise or something. if it was actual speech we're going to 
             * have bad luck in detecting very short phrases anyway.
             */
            if (testLens.length < 100) {
                System.out.println("SKIPPING:");
                System.out.println("");
                System.out.println("[***] PKT SEQUENCE TOO SHORT (i.e. noise) - PROBABLY NOT A MATCH FOR KNOWN PHRASE, len = " + testLens.length);
                System.out.println("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-");
                System.out.println("");
                continue;
            }
            
            System.out.println("***** SEQ " + (numSequences + 1) + ":");
            System.out.println("");
            System.out.println("*** test sequence is " + testLens.length + " pkts long");

            /* averageSequenceLen - let's chop sample sizes down to the average training
             * sequence length, since log scores are affected by sequence lengths.
             * it is therefore unfair to test a sequence 400 pkt sizes in length
             * if the avg training sequence length is say, 140. some normalisation method
             * such as z-scores would work here as well.
             */

            if (testLens.length > averageSequenceLen) {
                String[] testLensTemp = new String[averageSequenceLen];
                System.arraycopy(testLens, 0, testLensTemp, 0, averageSequenceLen);
                testLens = testLensTemp;
            }

            ArrayList<Symbol> tempSList = new ArrayList<Symbol>();

            for (String thisLen : testLens) {
                Integer tSize = Integer.parseInt(thisLen);

                if (symbolMap.containsKey(tSize.toString())) {
                    tempSList.add(symbolMap.get(tSize.toString()));
                } else {
                    /* hmm, symbol not in alphabet, it basically should be if there is enough training
                     * data..
                     */
                }
            }

            SymbolList mySymbolList = new SimpleSymbolList(alphabet, tempSList);
            StatePath path = null;
            StatePath nullPath = null;
            StatePath probability = null;
            try {

                if (dp == null) {
                    System.out.println("dp is null");
                }

                nullPath = dp.viterbi(new SymbolList[]{mySymbolList}, ScoreType.NULL_MODEL);
                path = dp.viterbi(new SymbolList[]{mySymbolList}, ScoreType.ODDS);

            } catch (Exception e) {
                e.printStackTrace();
            }

            System.out.println("");
            System.out.println("*** scoring threshold = " + scoreThreshold);
            System.out.println("*** calculated log-odds of sequence for trained model = " + path.getScore());
            System.out.println("");

            /* compare against scoring threshold. this number needs to be tweaked per-phrase/per-model. */
            if (path.getScore() >= scoreThreshold) {
                System.out.println("[***] POSSIBLE MATCH FOR KNOWN PHRASE");
                matches++;
            } else {
                System.out.println("[***] PROBABLY NOT A MATCH FOR KNOWN PHRASE");
            }
            
            numSequences++;
            System.out.println("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-");
            System.out.println("");

        }
        
        System.out.println("");
        System.out.println("**** matches in file: " + matches + " / " + numSequences);
        System.out.println("");
        System.out.print("enter another filename: ");

        return 0;

    }
}
