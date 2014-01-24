skypegrep
=========

A proof of concept to derive spoken phrases from encrypted Skype conversations.

Skypegrep's standard usage syntax is as follows:

sh-3.2# java -jar -Xmx3g skype.jar train <trainingData.pcap> <test.pcap> <scoreThreshold>

'scoreThreshold' should be determined on a per-model (i.e. per-phrase) basis to give low false positive and low false negative rate. One way to determine a sensible figure for the scoring threshold is to test several pcaps which are known to feature the utterance in question against the PHMM. For the sample data recorded, a reasonable scoring threshold is 185.0.

So, to test against a file called 'wrong.pcap', we may run skypegrep as follows:

sh-3.2# java -jar -Xmx3g skype.jar train darkSuit.pcap wrong19.pcap 185.0

*** parsing training data pcap file
*** removing silence & noise from training data
*** number of silent & noisy phases removed: 479
*** parsed training data file (darkSuite.pcap) successfully.
*** number of training sets: 402. average training sequence length: 147
*** alphabet size: 95

*** training Profile HMM
*** profile HMM trained..

*** parsing test sequence(s) pcap file..

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
***** SEQ 1:

*** test sequence is 281 pkts long

*** scoring threshold = 185.0
*** calculated log-odds of sequence for trained model = 173.40509252621132

[***] PROBABLY NOT A MATCH FOR KNOWN PHRASE
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-


**** matches in file: 0 / 1

enter another filename: 


The tool also offers a 'plotting mode', which allows payload length sequences to be plotted graphically vs. time. This feature was particularly useful during our research for comparing the "shapes" and features of payload length sequences in encrypted VoIP streams. Moreover, use of the plotting feature allows one to visually ascertain that identical or similar utterances do indeed result in similar plots each time. For syntax is:

sh-3.2# java -jar -Xmx3g skype.jar plot <data.pcap> <pktOffset> <numPkts>

So, using the included sample data:

sh-3.2# java -jar -Xmx3g skype.jar plot darkSuit.pcap 500 1000

*** extracting training data from pcap file
*** removing silence
*** number of silent phases removed: 2
