# PacketCapture-
Parsing Pcap files and capturing the different types of cyber attacks 

Goal 

To Capture the different types of cyber attacks that happen through network and get the packet count based on the attack type. 

Brainstroming 

Understanding of the different types of network attacks which have been discovered in the past and using python modules which parse and recognize these types of attacks.

Usage 

For Testing purpose mock data has been used.
In order to generate the data Wireshark would be an helpful tool which would capture the network packets at that present time and generate the .pcap extension files. 

To run in Linux/Unix Environment 

cmd: <pcap_parser.py> -o <pcap file with the path  > 
Example : ./pcap_parser.py -o /usr/test1.pcap

To run in Windows Environment 

IDE like PyCharm or IntelliJ based on the User choice 
Make sure to have the pcap file within the folder where the script is being run for ease of use or please provide the path of the pcap file in the run configuration settings of the IDE. 
