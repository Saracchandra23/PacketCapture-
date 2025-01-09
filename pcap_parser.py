#!/usr/bin/python

'''

The program goes through the pcap file 3 times if it's a tcp scan and 2 times if it's a udp scan
First the program counts the number unique packets based on the type of scan and based on the the counts
it makes a decision on the type of a scan

Second iteration of the pcap file creates sets based on the types of scans. It essentially build a data 
structure based on IP addresses, ports and type of packets 

Third iteration the propgram pirints the IP addresses and the scanned number of ports based on the built data
structures for the user
'''

import dpkt
import getopt
import sys
import socket

null_packet_counter=0
xmas_packet_counter=0
syn_packet_counter=0
syn_ack_packet_counter=0
ack_packet_counter=0
rst_ack_packet_counter=0
rst_packet_counter=0

typeOfScan = 0 #NULL=1, XMAS=2, SYN=3, CONNECT=4, UDP=5, WrongFile=0
sourceIPAddr = set([])          #unique Source IPs
destinationIPAddr = set([])     #unique Destination IPs
directionofScan=set([]) 

opts, filenamePCAP = getopt.getopt(sys.argv[1:], "-i")

with open(filenamePCAP[0]) as f:               #tcp_NULL_scan.pcap
	pcap = dpkt.pcap.Reader(f)

	count1 = 1;
	tcp_count=0;
	udp_count=0;
	for ts, buf in pcap:
		#print ts, len(buf)
		eth = dpkt.ethernet.Ethernet(buf)
		if eth.type == dpkt.ethernet.ETH_TYPE_ARP:   #ignore ARP packets
			#print count1,':ARP'
			count1 = count1
		elif eth.type == dpkt.ethernet.ETH_TYPE_IP:   #process the data
			count1 = count1
			#now we can assume the packet is an ip packet
			ip = eth.data
			if isinstance(ip.data, dpkt.tcp.TCP):
				#print count1,':TCP'
				tcp_count += 1  #increment the tcp_counter
				tcp = ip.data
				#print count1,':',tcp.dport
				#print count1,':',tcp.flags
				if tcp.flags == 0:   #0 is 0x00 for NULL packets
					null_packet_counter +=1
					#print count1,':','NULL Scan'
				elif tcp.flags == 41:   #41 is 0x29 for XMAS packets (PSH,FIN,URG)
					xmas_packet_counter +=1
					#print count1,':','Xmas Scan'
				elif tcp.flags == 2:   #2 is 0x02 for SYN packets
					syn_packet_counter +=1
					#print count1,':','SYN or Connect Scan'
				elif tcp.flags == 18:   #18 is 0x12 for SYN,ACK packets
					syn_ack_packet_counter +=1
					#print count1,':','SYN or Connect Scan'
				elif tcp.flags == 16:   #16 is 0x10 for ACK packets
					ack_packet_counter +=1
					#print count1,':','Connect Scan'
				elif tcp.flags == 4:   #4 is 0x04 for RST packets
					rst_packet_counter +=1
					#print count1,':','SYN or Connect Scan'
				elif tcp.flags == 20:   #20 is 0x14 for RST,ACK packets
					rst_ack_packet_counter +=1
					#print count1,':','SYN or Connect Scan'
			elif isinstance(ip.data, dpkt.udp.UDP):
				#print count1,':UDP'
				udp_count += 1 
			elif isinstance(ip.data, dpkt.icmp.ICMP):
				#print count1,':ICMP'
				count1 = count1
		else:
			#print count1,':Something else'
			count1 = count1
		count1 +=1	

	if tcp_count > udp_count:
		if null_packet_counter > 0 and null_packet_counter > syn_packet_counter:
			#print 'NULL Scan file\n'
			typeOfScan=1
		elif xmas_packet_counter > 0 and xmas_packet_counter > null_packet_counter and xmas_packet_counter > syn_packet_counter:
			#print 'XMAS Scan file\n'
			typeOfScan=2
		elif syn_packet_counter > 0 and syn_packet_counter > null_packet_counter and syn_packet_counter > xmas_packet_counter:
			if syn_ack_packet_counter > ack_packet_counter:
				#print 'SYN(Half Open) Scan\n'
				typeOfScan=3
			else:
				#print 'Connect Scan\n'
				typeOfScan=4

	elif udp_count > tcp_count and udp_count>0: #could have used else instead of elif
		#print 'UDP Scan\n'
		typeOfScan=5

	f.seek(0)        #can't find a better way to reinitialize "pcap" data structure
	pcap = dpkt.pcap.Reader(f)

	for ts, buf in pcap:               #iterate again and figureout??? Finding source and destination IP Addresses
		eth = dpkt.ethernet.Ethernet(buf)

		if eth.type == dpkt.ethernet.ETH_TYPE_IP:   #process the data
			count1 = count1
			#now we can assume the packet is an ip packet
			ip = eth.data
			if isinstance(ip.data, dpkt.tcp.TCP):
				tcp = ip.data
				if typeOfScan ==1:  #it's a NULL scan file
					if tcp.flags == 0:   #0 is 0x00 for NULL packets
						sourceIPAddr.add(socket.inet_ntoa(ip.src))
						destinationIPAddr.add(socket.inet_ntoa(ip.dst))
						directionTuple = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),tcp.dport
						directionofScan.add(directionTuple)

				elif typeOfScan ==2:  #it's a XMAS scan file
					if tcp.flags == 41:   #41 is 0x029 for XMAS packets
						sourceIPAddr.add(socket.inet_ntoa(ip.src))
						destinationIPAddr.add(socket.inet_ntoa(ip.dst))
						directionTuple = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),tcp.dport
						directionofScan.add(directionTuple)

				elif typeOfScan ==3 or typeOfScan ==4:  #it's a SYN or connect scan file
					if tcp.flags == 2:   #2 is 0x02 for SYN packets
						sourceIPAddr.add(socket.inet_ntoa(ip.src))
						destinationIPAddr.add(socket.inet_ntoa(ip.dst))
						directionTuple = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),tcp.dport
						directionofScan.add(directionTuple)

				#elif typeOfScan ==5:
				#	cout1=count1 #udp file
				#else:
				#	print 'Something is not correct, can not find a valid scan type'
			elif isinstance(ip.data, dpkt.udp.UDP):
				udp = ip.data
				a = udp.ulen
				if a == 8:
					sourceIPAddr.add(socket.inet_ntoa(ip.src))
					destinationIPAddr.add(socket.inet_ntoa(ip.dst))
					directionTuple = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),udp.dport
					directionofScan.add(directionTuple)

	tempList = list(directionofScan)
	#print 'TempList is'
	#print tempList

	if typeOfScan == 1:
		print 'NULL Scan'
		countidx=0
		IPPortDict={} 
		for DirectionPortTuple in tempList:
			IPPortDict[DirectionPortTuple] =  [1,0,0]  #None/NULL=1,RST_ACK=0,RST=0
			#print 'Tempaddr:',destAddrTemp
		#print IPPortDict
		#print len(IPPortDict)

		#let's go through the file again

		f.seek(0)        #can't find a better way to reinitialize "pcap" data structure
		pcap = dpkt.pcap.Reader(f)
		count1 = 0
		for ts, buf in pcap:               #iterate again and figureout??? the flags of the dictionary
			eth = dpkt.ethernet.Ethernet(buf)

			if eth.type == dpkt.ethernet.ETH_TYPE_IP:   #process the data
				count1 = count1
				#now we can assume the packet is an ip packet
				ip = eth.data
				if isinstance(ip.data, dpkt.tcp.TCP):
					tcp = ip.data

					if tcp.flags == 20:  #RST_ACK
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #if destination
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[1]=1          #make the RST_ACK flag 1 of destination
							IPPortDict[directionTuple1] = tempList

					elif tcp.flags == 4:  #RST
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[2]=1          #make the RST flag 1 of destination
							IPPortDict[directionTuple1] = tempList

					
		#print IPPortDict
		#print len(IPPortDict)
		portCountList=[]
		destinationIndex=0;
		destinationIPAddrList = list(destinationIPAddr)
		#print destinationIPAddrList
		for addr in destinationIPAddrList:  #counting the ports for each destination IP
			portCountTemp = 0
			portClosedCountTemp=0
			#print 'addr:',addr
			for DirectionPortTuple, values in IPPortDict.iteritems():
				destAddrTemp =  DirectionPortTuple[1]  #get the destination IP address of each tuple
				#print 'Tempaddr:',destAddrTemp
				if addr == destAddrTemp:
					portCountTemp +=1
					tempSum = sum(values) # add the values in the list of each matching dictionary key
					if tempSum > 1:
						portClosedCountTemp +=1
				#print portCountTemp
			portCountTuple =(portCountTemp,portClosedCountTemp)
			portCountList.append(portCountTuple)
			destinationIndex +=1
		#print portCountList
		
		countidx=0
		for i in portCountList:
			if portCountList[countidx][0] > 0:
				print destinationIPAddrList[countidx],':','Total ports scanned: ',portCountList[countidx][0],' ,Total closed ports: ',portCountList[countidx][1]
				print ''
			countidx +=1
		
	elif typeOfScan == 2:
		print 'XMAS Scan'
		countidx=0
		IPPortDict={} 
		for DirectionPortTuple in tempList:
			IPPortDict[DirectionPortTuple] =  [1,0,0]  #XMAS=1,RST_ACK=0,RST=0
			#print 'Tempaddr:',destAddrTemp
		#print IPPortDict
		#print len(IPPortDict)

		#let's go through the file again

		f.seek(0)        #can't find a better way to reinitialize "pcap" data structure
		pcap = dpkt.pcap.Reader(f)
		count1 = 0
		for ts, buf in pcap:               #iterate again and figureout??? the flags of the dictionary
			eth = dpkt.ethernet.Ethernet(buf)

			if eth.type == dpkt.ethernet.ETH_TYPE_IP:   #process the data
				count1 = count1
				#now we can assume the packet is an ip packet
				ip = eth.data
				if isinstance(ip.data, dpkt.tcp.TCP):
					tcp = ip.data

					if tcp.flags == 20:  #RST_ACK
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #if destination
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[1]=1          #make the RST_ACK flag 1 of destination
							IPPortDict[directionTuple1] = tempList

					elif tcp.flags == 4:  #RST
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[2]=1          #make the RST flag 1 of destination
							IPPortDict[directionTuple1] = tempList

					
		#print IPPortDict
		#print len(IPPortDict)

		portCountList=[]
		destinationIndex=0;
		destinationIPAddrList = list(destinationIPAddr)
		#print destinationIPAddrList
		for addr in destinationIPAddrList:  #counting the ports for each destination IP
			portCountTemp = 0
			portClosedCountTemp=0
			#print 'addr:',addr
			for DirectionPortTuple, values in IPPortDict.iteritems():
				destAddrTemp =  DirectionPortTuple[1]  #get the destination IP address of each tuple
				#print 'Tempaddr:',destAddrTemp
				if addr == destAddrTemp:
					portCountTemp +=1
					tempSum = sum(values) # add the values in the list of each matching dictionary key
					if tempSum > 1:
						portClosedCountTemp +=1
				#print portCountTemp
			portCountTuple =(portCountTemp,portClosedCountTemp)
			portCountList.append(portCountTuple)
			destinationIndex +=1
		#print portCountList

		countidx=0
		for i in portCountList:
			if portCountList[countidx][0] > 0:
				print destinationIPAddrList[countidx],':','Total ports scanned: ',portCountList[countidx][0],' ,Total closed ports: ',portCountList[countidx][1]
				print ''
			countidx +=1


	elif typeOfScan == 3:
		print 'Half-open (SYN) Scan'
		countidx=0
		IPPortDict={} 
		for DirectionPortTuple in tempList:
			IPPortDict[DirectionPortTuple] =  [1,0,0,0,0,0]  #SYN=1,RST_ACK=0,RST=0,SYN_ACK=0,RST_ACK=0,RST=0
			#print 'Tempaddr:',destAddrTemp
		#print IPPortDict
		#print len(IPPortDict)

		#let's go through the file again

		f.seek(0)        #can't find a better way to reinitialize "pcap" data structure
		pcap = dpkt.pcap.Reader(f)
		count1 = 0
		for ts, buf in pcap:               #iterate again and figureout??? the flags of the dictionary
			eth = dpkt.ethernet.Ethernet(buf)

			if eth.type == dpkt.ethernet.ETH_TYPE_IP:   #process the data
				count1 = count1
				#now we can assume the packet is an ip packet
				ip = eth.data
				if isinstance(ip.data, dpkt.tcp.TCP):
					tcp = ip.data
					if tcp.flags == 18:  #Syn_ACK
						directionTuple = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #it has to come from the destination, switch
						if directionTuple in IPPortDict:
							tempList = IPPortDict[directionTuple]
							tempList[3]=1          #make the SYN_ACK flag 1
							IPPortDict[directionTuple] = tempList

					elif tcp.flags == 20:  #RST_ACK
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #if destination
						directionTuple2 = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),tcp.dport #if source
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[4]=1          #make the RST_ACK flag 1 of destination
							IPPortDict[directionTuple1] = tempList

						elif directionTuple2 in IPPortDict:  #coming from the source (open port?)
							tempList = IPPortDict[directionTuple2]
							tempList[1]=1          #make the RST_ACK flag 1 of source
							IPPortDict[directionTuple2] = tempList

					elif tcp.flags == 4:  #RST
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #
						directionTuple2 = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),tcp.dport
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[5]=1          #make the RST flag 1 of destination
							IPPortDict[directionTuple1] = tempList

						elif directionTuple2 in IPPortDict:  #coming from the source (open port?)
							tempList = IPPortDict[directionTuple2]
							tempList[2]=1          #make the RST flag 1 of source
							IPPortDict[directionTuple2] = tempList
					
		#print IPPortDict
		#print len(IPPortDict)

		portCountList=[]
		destinationIndex=0;
		destinationIPAddrList = list(destinationIPAddr)
		#print destinationIPAddrList
		for addr in destinationIPAddrList:  #counting the ports for each destination IP
			portCountTemp = 0
			portClosedCountTemp=0
			portOpenCountTemp=0
			portFilteredCountTemp=0
			#print 'addr:',addr
			for DirectionPortTuple, values in IPPortDict.iteritems():
				destAddrTemp =  DirectionPortTuple[1]  #get the destination IP address of each tuple
				#print 'Tempaddr:',destAddrTemp
				if addr == destAddrTemp:
					
					tempSum = sum(values) # add the values in the list of each matching dictionary key
					if tempSum > 2:
						portOpenCountTemp +=1
						portCountTemp +=1
					elif tempSum > 1:
						portClosedCountTemp +=1
						portCountTemp +=1
					
				#print portCountTemp
			portCountTuple =(portCountTemp,portClosedCountTemp,portOpenCountTemp,portFilteredCountTemp)
			portCountList.append(portCountTuple)
			destinationIndex +=1
		#print portCountList

		countidx=0
		for i in portCountList:
			if portCountList[countidx][0] > 0:
				print destinationIPAddrList[countidx],':','Total ports scanned: ',portCountList[countidx][0],' ,Total closed ports: ',portCountList[countidx][1], ' ,Total Open ports: ',portCountList[countidx][2]
				print ''
			countidx +=1

	elif typeOfScan == 4:
		print 'Connect Scan'
		countidx=0
		IPPortDict={} 
		for DirectionPortTuple in tempList:
			IPPortDict[DirectionPortTuple] =  [1,0,0,0,0,0,0,0]  #SYN=1,ACK=0,RST_ACK=0,RST=0,SYN_ACK=0,ACK=0,RST_ACK=0,RST=0 (first 4 scanner last 4 target)
			#print 'Tempaddr:',destAddrTemp
		#print IPPortDict
		#print len(IPPortDict)

		#let's go through the file again

		f.seek(0)        #can't find a better way to reinitialize "pcap" data structure
		pcap = dpkt.pcap.Reader(f)
		count1 = 0
		for ts, buf in pcap:               #iterate again and figureout??? the flags of the dictionary
			eth = dpkt.ethernet.Ethernet(buf)

			if eth.type == dpkt.ethernet.ETH_TYPE_IP:   #process the data
				count1 = count1
				#now we can assume the packet is an ip packet
				ip = eth.data
				if isinstance(ip.data, dpkt.tcp.TCP):
					tcp = ip.data
					if tcp.flags == 18:  #Syn_ACK
						directionTuple = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #it has to come from the destination, switch
						if directionTuple in IPPortDict:
							tempList = IPPortDict[directionTuple]
							tempList[4]=1          #make the SYN_ACK flag 1
							IPPortDict[directionTuple] = tempList

					elif tcp.flags == 16:  #ACK
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #
						directionTuple2 = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),tcp.dport
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[5]=1          #make the ACK flag 1 of destination
							IPPortDict[directionTuple1] = tempList

						elif directionTuple2 in IPPortDict:  #coming from the source (open port?)
							tempList = IPPortDict[directionTuple2]
							tempList[1]=1          #make the RST_ACK flag 1 of source
							IPPortDict[directionTuple2] = tempList

					elif tcp.flags == 20:  #RST_ACK
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #
						directionTuple2 = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),tcp.dport
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[6]=1          #make the RST_ACK flag 1 of destination
							IPPortDict[directionTuple1] = tempList

						elif directionTuple2 in IPPortDict:  #coming from the source (open port?)
							tempList = IPPortDict[directionTuple2]
							tempList[2]=1          #make the RST_ACK flag 1 of source
							IPPortDict[directionTuple2] = tempList

					elif tcp.flags == 4:  #RST
						directionTuple1 = socket.inet_ntoa(ip.dst),socket.inet_ntoa(ip.src),tcp.sport #it has to come from the destian, switch
						directionTuple2 = socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),tcp.dport
						if directionTuple1 in IPPortDict:  #coming from the destination (closed port)
							tempList = IPPortDict[directionTuple1]
							tempList[7]=1          #make the RST flag 1 of destination
							IPPortDict[directionTuple1] = tempList

						elif directionTuple2 in IPPortDict:  #coming from the source (open port?)
							tempList = IPPortDict[directionTuple2]
							tempList[3]=1          #make the RST flag 1 of source
							IPPortDict[directionTuple2] = tempList
					
		#print IPPortDict
		#print len(IPPortDict)

		portCountList=[]
		destinationIndex=0;
		destinationIPAddrList = list(destinationIPAddr)
		#print destinationIPAddrList
		for addr in destinationIPAddrList:  #counting the ports for each destination IP
			portCountTemp = 0
			portClosedCountTemp=0
			portOpenCountTemp=0
			portFilteredCountTemp=0
			#print 'addr:',addr
			for DirectionPortTuple, values in IPPortDict.iteritems():
				destAddrTemp =  DirectionPortTuple[1]  #get the destination IP address of each tuple
				#print 'Tempaddr:',destAddrTemp
				if addr == destAddrTemp:
					
					tempSum = sum(values) # add the values in the list of each matching dictionary key
					if tempSum > 3:
						portCountTemp +=1
						portOpenCountTemp +=1
					elif tempSum > 1:
						portCountTemp +=1
						portClosedCountTemp +=1

				#print portCountTemp
			portCountTuple =(portCountTemp,portClosedCountTemp,portOpenCountTemp,portFilteredCountTemp)
			portCountList.append(portCountTuple)
			destinationIndex +=1
		#print portCountList

		countidx=0
		for i in portCountList:
			if portCountList[countidx][0] > 0:
				print destinationIPAddrList[countidx],':','Total ports scanned: ',portCountList[countidx][0],' ,Total closed ports: ',portCountList[countidx][1], ' ,Total Open ports: ',portCountList[countidx][2]
				print ''
			countidx +=1

	elif typeOfScan == 5:
		print 'UDP Scan'
		countidx=0
		IPPortDict={} 
		for DirectionPortTuple in tempList:
			IPPortDict[DirectionPortTuple] =  [1]  #already it should have the correct udp port list
			#print 'Tempaddr:',destAddrTemp
		#print IPPortDict
		#print len(IPPortDict)

		#let's go through the file again

		portCountList=[]
		destinationIndex=0;
		destinationIPAddrList = list(destinationIPAddr)
		#print destinationIPAddrList
		for addr in destinationIPAddrList:  #counting the ports for each destination IP
			portCountTemp = 0
			portClosedCountTemp=0
			portOpenCountTemp=0
			portFilteredCountTemp=0
			#print 'addr:',addr
			for DirectionPortTuple, values in IPPortDict.iteritems():
				destAddrTemp =  DirectionPortTuple[1]  #get the destination IP address of each tuple
				#print 'Tempaddr:',destAddrTemp
				if addr == destAddrTemp:
					portCountTemp +=1
				#print portCountTemp
			portCountTuple =(portCountTemp,0,0,0)
			portCountList.append(portCountTuple)
			destinationIndex +=1
		#print portCountList

		countidx=0
		for i in portCountList:
			if portCountList[countidx][0] > 0:
				print destinationIPAddrList[countidx],':','Total ports scanned: ',portCountList[countidx][0]
				print ''
			countidx +=1	

#converting the direction of Scan set (only unique directions) to a list so that I can index 
#directionofScanList =list(directionofScan)

'''
print "NULL packets: ",null_packet_counter
print "XMAS packets: ",xmas_packet_counter
print "SYN packets: ",syn_packet_counter
print "SYN,ACK packets: ",syn_ack_packet_counter
print "ACK packets: ",ack_packet_counter
print "RST packets: ",rst_packet_counter
print "RST,ACK packets: ",rst_ack_packet_counter
print ''
print sourceIPAddr
print destinationIPAddr
print ''
#print directionofScanList
print len(directionofScanList)
'''
