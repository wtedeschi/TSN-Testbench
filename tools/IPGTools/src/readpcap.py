import os
import math
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import argparse
import pathlib
import seaborn as sns

import binascii
from datetime import datetime

from beautifultable import BeautifulTable

from scapy.all import *
from scapy.utils import RawPcapReader, RawPcapNgReader, PcapReader
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, TCP
import io


preambleLength = 7 + 1
crcLength = 4
headerLenght = 18 #With Vlan
fullOverhead = preambleLength + crcLength + headerLenght

Noframes={'Hi':64, 'Low':32, 'RT':16}
PcPValue={'Hi':6, 'Low':5, 'RT':4}

tclass_cycle_time = 0.0005

class Stats:
    def __init__(self):
        self.IPG={"count":0, "mean": 0, "std" "min": 0, "Q25":0, "Q50":0, "Q75":0, "max":0}
        self.BatchStart={"count":0, "mean": 0, "std" "min": 0, "Q25":0, "Q50":0, "Q75":0, "max":0}
        self.BatchEnd={"count":0, "mean": 0, "std" "min": 0, "Q25":0, "Q50":0, "Q75":0, "max":0}
        self.BatchCount={"count":0, "mean": 0, "std" "min": 0, "Q25":0, "Q50":0, "Q75":0, "max":0}
        self.cycles = 0
        self.packetLenght = 0


def create_main_table():
    global tclass_start_cycle
    ipgTable = BeautifulTable(precision=4)
    ipgTable.rows.append(["count","min", "mean", "std", "Q25", "Q50", "Q75", "max"])
    ipgTable.columns.width = [14, 14, 14, 14, 14, 14, 14, 14]
    ipgTable.border.left = ''
    ipgTable.border.right = ''
    ipgTable.border.top = ''
    ipgTable.border.bottom = ''

    # Batch Count
    bcTable = BeautifulTable(precision=4)
    bcTable.rows.append(["min", "mean", "max"])
    bcTable.columns.width = [5, 6, 5]
    bcTable.border.left = ''
    bcTable.border.right = ''
    bcTable.border.top = ''
    bcTable.border.bottom = ''
    # Batch Start
    bsTable = BeautifulTable(precision=4)
    bsTable.rows.append(["min", "mean", "max"])
    bsTable.columns.width = [14, 14, 14]
    bsTable.border.left = ''
    bsTable.border.right = ''
    bsTable.border.top = ''
    bsTable.border.bottom = ''
    # Batch End
    beTable = BeautifulTable(precision=4)
    beTable.rows.append(["min", "mean", "max"])
    beTable.columns.width = [14, 14, 14]
    beTable.border.left = ''
    beTable.border.right = ''
    beTable.border.top = ''
    beTable.border.bottom = ''

    # Main table
    mainTable = BeautifulTable(maxwidth=500)
    #mainTable.columns.header = [ "Traffic Class",
    #                             "Cycles",
    #                             "Pkt Len",
    #                            "Batch Count",
    #                             "IPG",
    #                             "Batch Start",
    #                             "Batch End" ]
    
    mainTable.columns.header = [ "Traffic Class",
                                 "Cycles",
                                 "Pkt Len",
                                "Batch Count",
                                 "IPG" ]
    #mainTable.rows.append(["Cycle Time (s)", tclass_cycle_time, "", bcTable, ipgTable,
    #                          bsTable, beTable])

    mainTable.rows.append(["Cycle Time (s)", tclass_cycle_time, "", bcTable, ipgTable])

    return mainTable

def populate_stats(stats, className ,table):
    global tclass_start_cycle
    resultIPGTable = BeautifulTable(precision=4)
    resultIPGTable.rows.append([stats.IPG["count"],
                                stats.IPG["min"],
                                stats.IPG["mean"],
                                stats.IPG["std"],
                                stats.IPG["Q25"],
                                stats.IPG["Q50"],
                                stats.IPG["Q75"],
                                stats.IPG["max"]])

    resultIPGTable.columns.width = [14, 14, 14, 14, 14, 14, 14, 14]
    resultIPGTable.border.left = ''
    resultIPGTable.border.right = ''
    resultIPGTable.border.top = ''
    resultIPGTable.border.bottom = ''

    resultBCTable = BeautifulTable(precision=0)
    resultBCTable.rows.append([stats.BatchCount["min"],
                               stats.BatchCount["mean"],
                               stats.BatchCount["max"] ])
    resultBCTable.columns.width = [5, 6, 5]
    resultBCTable.border.left = ''
    resultBCTable.border.right = ''
    resultBCTable.border.top = ''
    resultBCTable.border.bottom = ''

    resultBSTable = BeautifulTable(precision=6)
    resultBSTable.rows.append([ stats.BatchStart["min"],
                                stats.BatchStart["mean"],
                                stats.BatchStart["max"]])
    resultBSTable.columns.width = [14, 14, 14]
    resultBSTable.border.left = ''
    resultBSTable.border.right = ''
    resultBSTable.border.top = ''
    resultBSTable.border.bottom = ''

    resultBETable = BeautifulTable(precision=6)
    resultBETable.rows.append([stats.BatchEnd["min"],
                               stats.BatchEnd["mean"],
                               stats.BatchEnd["max"]])
    resultBETable.columns.width = [14, 14, 14]
    resultBETable.border.left = ''
    resultBETable.border.right = ''
    resultBETable.border.top = ''
    resultBETable.border.bottom = ''
    #table.rows.append([className,
    #                   stats.cycles,
    #                   stats.packetLenght,
    #                   resultBCTable,
    #                   resultIPGTable,
    #                   resultBSTable,
    #                   resultBETable])
    table.rows.append([className,
                       stats.cycles,
                       stats.packetLenght,
                       resultBCTable,
                       resultIPGTable])


def cycleOffset(cycleCounter, pkt_time, startTime):
    global tclass_cycle_time
    currCycleTime= (cycleCounter - 1) * tclass_cycle_time
    deltaTime = pkt_time - startTime
    #if cycleCounter < 4:
    res = deltaTime - currCycleTime
    return res

class TrafficClass:
    global tclass_start_cycle
    def __init__(self,pcp, tcName, nofFrames):
        self.pcp = pcp
        self.tcName = tcName
        self.nofFrames = nofFrames
        self.DeltaTime=[]
        self.DTimeTime=[]
        self.IPG=[]
        self.IPGTime=[]
        self.framesWithinCycle=[]
        self.framesWithinCycleTime=[]
        self.burstStartTime=[]
        self.batch_End=[]
        self.batch_Start=[]
        self.burstTime=[]
        self.aveIPGInBurst=[]
        self.lengths=[]
        self.deltaPktTime = 0
        self.prevPktTime= 0
        self.curpktTime = 0
        self.bytesStransmitedPerBurst = 0
        self.bellowThres_counter = 0
        self.countAll = 0
        self.countIPG = 0
        self.prevPktLength = 0
        self.cycleCounter = 0
        self.curCycleTime = 0
        self.transmitTime = 0
        self.burstTimeStart = 0
        self.burstTimeEnd = 0
        self.nextLowCounter = 0
        self.nextHighCounter = 0
        self.missingWithinACycle = 0
        self.cur_batch_end = 0
        self.cur_batch_start = 0
        self.cur_cycle_time = 0       
        self.dataframeIPG = None
        self.dataframeAveIPG = None
        self.stats = Stats()
    
    def missingPackets(self, pkt):
        missing = 0
        if self.countAll == 0:
            self.nextLowCounter = int.from_bytes(pkt.load[2:9], "big") + 1
            self.nextHighCounter = int.from_bytes(pkt.load[9:10], "big")
            if  self.nextLowCounter == 256:
                self.nextHighCounter = self.nextHighCounter + 1 
                self.nextLowCounter = int.from_bytes(pkt.load[2:9], "big")
        else:
            currentLowCounter = int.from_bytes(pkt.load[9:10], "big")
            currentHighCounter = int.from_bytes(pkt.load[2:9], "big")
            if currentLowCounter > self.nextLowCounter:
                missing = self.nextLowCounter - currentLowCounter
            elif currentLowCounter < self.nextLowCounter:
                missing = currentLowCounter + (256 - self.nextLowCounter)
            if currentLowCounter == 255:
                self.nextLowCounter = 0
                self.nextHighCounter = self.nextHighCounter + 1
            else:
                self.nextLowCounter = self.nextLowCounter + 1
        if missing > 0:
            print ("Missing " + str(missing))
        return missing

    def processPkt(self, pkt, deltaPktTime_threshold, initialTime):
        #print(int.from_bytes(pkt.load[9:10], "big"),
        #int.from_bytes(pkt.load[2:9], "big"),
        #pkt.load[10:34].decode("utf-8"))
        
        #missing = self.missingPackets(pkt)
        global tclass_cycle_time
        global fullOverhead
        if self.countAll > 0:
            self.prevPktTime = self.curpktTime
            self.deltaPktTime = pkt.time - self.prevPktTime
        self.curpktTime = pkt.time

        # Parsing is in the middle of the burst
        if self.deltaPktTime < deltaPktTime_threshold and self.deltaPktTime != 0:
            self.bellowThres_counter = self.bellowThres_counter + 1
            self.IPG.append(float((self.deltaPktTime - self.transmitTime) * 1e6))
            self.IPGTime.append(float(pkt.time))
            self.countIPG = self.countIPG + 1

        # Parsing is starting a new burst
        else:
            self.framesWithinCycle.append(self.bellowThres_counter + 1)
            self.framesWithinCycleTime.append(pkt.time)
            self.bellowThres_counter = 0
            self.missingWithinACycle = 0
            self.burstTimeEnd = self.prevPktTime


            
            # Beyond the first cycle we to take note of some numbers
            if self.cycleCounter >= 1:
                if self.cycleCounter >= 2:
                    self.batch_End.append(cycleOffset(self.cycleCounter - 1, self.prevPktTime, initialTime))
                    self.batch_Start.append(cycleOffset(self.cycleCounter, self.curpktTime, initialTime))
                burstTime = self.burstTimeEnd - self.burstTimeStart
                timeInTransmit = (self.bytesStransmitedPerBurst - self.prevPktLength)  * 8 / 1e9
                self.burstTime.append(float(burstTime))
                aveIPG = (burstTime - timeInTransmit)/(self.nofFrames - 1)
                self.aveIPGInBurst.append(float(aveIPG) * 1e6)
                self.bytesStransmitedPerBurst = len(pkt.load)  + fullOverhead
        


            self.burstTimeStart = self.curpktTime
            self.cycleCounter = self.cycleCounter + 1
            self.bytesStransmitedPerBurst = 0
        pktLen = headerLenght + len(pkt.load)
        if pktLen not in self.lengths:
            self.lengths.append(pktLen)
        self.DeltaTime.append(self.deltaPktTime)
        self.DTimeTime.append(pkt.time)
        self.prevPktLength = len(pkt.load)  + fullOverhead
        self.bytesStransmitedPerBurst = self.bytesStransmitedPerBurst + self.prevPktLength 
        self.transmitTime = (self.prevPktLength * 8) / 1e9
        self.countAll = self.countAll + 1    

    def plotMe(self, fileName):
        #fig, axs = plt.subplots(3, 1, sharex=True)
        #fig.suptitle(self.tcName + " " + str(self.prevPktLength) + "bytes x" + str(self.nofFrames) )
        #axs[0].plot(range(0, self.countAll), self.DeltaTime , 'ro')
        #axs[0].set_title('Delta Time between packets')
        #axs[0].set(xlabel='Count unit', ylabel='Delta in us')
        #axs[1].plot(range(0, self.countIPG), self.IPG , 'ro')
        #axs[1].set_title('IPG (us)')
        #axs[1].set(xlabel='count unit', ylabel='IPG in us')
        #axs[2].plot(range (0, self.cycleCounter), self.framesWithinCycle , 'ro')
        #Title = 'Frames per burst ' + str(self.nofFrames)
        #axs[2].set_title(Title)
        #axs[2].set(xlabel='Period Index', ylabel='Count of frames per burst')
        #plt.show()
        if len(self.DeltaTime) == 0:
            return
        print(self.lengths)
        fig, axs = plt.subplots(3, 1, sharex=True)
        fig.suptitle(self.tcName + " " + str(self.prevPktLength) + "bytes x" + str(self.nofFrames) + " Time trace" )
        axs[0].plot(self.DTimeTime, self.DeltaTime , 'ro')
        axs[0].set_title('Delta Time between packets')
        axs[0].set(xlabel='Time(s)', ylabel='Delta in us')
        axs[1].plot(self.IPGTime, self.IPG , 'ro')
        axs[1].set_title('IPG (us)')
        axs[1].set(xlabel='Time', ylabel='IPG in us')
        axs[2].plot(self.framesWithinCycleTime, self.framesWithinCycle , 'ro')
        Title = 'Frames per burst ' + str(self.nofFrames)
        axs[2].set_title(Title)
        axs[2].set(xlabel='Period Index', ylabel='Count of frames per burst')
        plt.savefig('books_read.png')
        plt.show()
        
    def getDataFrameIPG(self):
        title = self.tcName + ': ' + str(self.prevPktLength) + "bytes x" + str(self.nofFrames)
        print(title)
        self.dataframeIPG = pd.DataFrame(self.IPG[:])
        self.dataframeIPG.set_axis({title}, axis=1, inplace=True)
        return self.dataframeIPG

    def getLengths(self):
        print(self.lengths)
        return ' - '.join(str(le) for le in self.lengths)
    
    def getDataFrameIPGwithinBurst(self):
        title = self.tcName + ': ' + str(self.nofFrames) + ' within the burst'
        print(title)
        self.dataframeAveIPG = pd.DataFrame(self.aveIPGInBurst[:])
        self.dataframeAveIPG.set_axis({title}, axis=1, inplace=True)
        return self.dataframeAveIPG
    
    def describe(self):
        self.dataframeIPG = self.getDataFrameIPG()
        print(self.dataframeIPG.describe()) 
        print(self.getDataFrameIPGwithinBurst().describe()) 

    def getStats(self):
        df = pd.DataFrame(self.batch_End[:])
        self.stats.BatchEnd['count'] = float(df.count())
        self.stats.BatchEnd['min'] = float(df.min())
        self.stats.BatchEnd['max'] = float(df.max())
        self.stats.BatchEnd['mean'] = float(df.mean())
        self.stats.BatchEnd['std'] = float(df.std())
        self.stats.BatchEnd['Q25'] = df.quantile(.25)
        self.stats.BatchEnd['Q50'] = df.quantile(.50)
        self.stats.BatchEnd['Q75'] = df.quantile(.75)
        
        df = pd.DataFrame(self.batch_Start[:])
        self.stats.BatchStart['min'] = float(df.min())
        self.stats.BatchStart['max'] = float(df.max())
        self.stats.BatchStart['mean'] = float(df.mean())
        
        df = pd.DataFrame(self.IPG[:])
        self.stats.IPG['count'] = float(df.count())
        self.stats.IPG['min'] = float(df.min())
        self.stats.IPG['max'] = float(df.max())
        self.stats.IPG['mean'] = float(df.mean())  
        self.stats.IPG['std'] = float(df.std())
        self.stats.IPG['Q25'] = float(df.quantile(.25))
        self.stats.IPG['Q50'] = float(df.quantile(.50))
        self.stats.IPG['Q75'] = float(df.quantile(.75))
        
        df = pd.DataFrame(self.framesWithinCycle[1:])
        self.stats.BatchCount['min'] = int(df.min())
        self.stats.BatchCount['max'] = int(df.max())
        self.stats.BatchCount['mean'] = int(df.mean())
        self.stats.cycles = self.cycleCounter
        self.stats.packetLenght = self.getLengths()
        return self.stats
    
    def hasDataAvailable(self):
        return 1 if len(self.DeltaTime) != 0 else 0

pktCounter = []
pktTime = []
pcp = []


def print_payload(pkt):
    message = pkt.payload.payload.decode()
    message_len = len(message)
    left = 0
    right = 8
    loop = int(message_len / 16) + 1
    for i in range(loop):
        print(' '*8, i, ' :', binascii.hexlify(message[left:right]),
                              binascii.hexlify(message[left+8:right+8]))
        left += 16
        right += 16

def process_pcap(file_name, investigation, start, end):
    
    TrafficClasses={'Hi': TrafficClass(6,'TSN High', Noframes['Hi']),
                    'Low':TrafficClass(5, 'TSN Low', Noframes['Low']),
                    'RT': TrafficClass(4, 'RT Cyclic', Noframes['RT'])}

    print('Opening {}...'.format(file_name))
 
    initialPrio = 0
    flipped = False

    deltaPkt_threshold = tclass_cycle_time / 3.0
    initialTime = 0
    interesting_packet_count = 0
    count = 0
    tclass_start_cycle = 0
    local_file = open(file_name, "rb")
    r = PcapReader(local_file)
    while count < end:
        try:
            pkt = r.next()
        except StopIteration:
            print("No more samples at right =", right)
            break
        
        count += 1
        
        if investigation and count >= 500:
            print("Breaking")
            print(len(pkt.load))
            print(type(pkt))
            break
       
        if count > end and end != 0:
            break
       
        if pkt.type == 0x8100:
            vlan_pkt = pkt[Dot1Q]

            if (initialTime == 0):
                initialTime = pkt.time
            pktCounter.append(count)
            pktTime.append(float(pkt.time))
            prio = vlan_pkt.fields["prio"]
            pcp.append(vlan_pkt.fields["prio"])
            
            if initialPrio == 0:
                initialPrio = prio
            
            if not flipped and initialPrio != prio:
                flipped = True
                
                #continue
            
            if not flipped:
                continue
            
            if (prio == PcPValue['Hi']):
                if tclass_start_cycle == 0:
                    tclass_start_cycle = pkt.time
                TrafficClasses['Hi'].processPkt(pkt, deltaPkt_threshold, tclass_start_cycle)

            elif (prio == PcPValue['Low']):
                TrafficClasses['Low'].processPkt(pkt, deltaPkt_threshold, tclass_start_cycle)
            
            elif (prio == PcPValue['RT']):
                TrafficClasses['RT'].processPkt(pkt, deltaPkt_threshold, tclass_start_cycle)
        continue
        
        interesting_packet_count += 1
       

    plt.plot(pktCounter, pcp , 'ro')
    plt.title('Packet order')
    plt.ylabel('PSP value')
    plt.xlabel('Count units')       
    plt.show()
    
    
    plt.plot(pktTime, pcp , 'ro')
    plt.title('Packet order in time')
    plt.ylabel('PSP value')
    plt.xlabel('Time')       
    plt.show()

    
    for key in TrafficClasses:
        TrafficClasses[key].plotMe(file_name)
        #TrafficClasses[key].describe()
    
    mainTable = create_main_table()
    for key in TrafficClasses:
        if TrafficClasses[key].hasDataAvailable():
            stats = TrafficClasses[key].getStats()
            populate_stats(stats, key, mainTable)
    print(mainTable)
    
    names = [key for key in TrafficClasses if TrafficClasses[key].hasDataAvailable()]
    framesToConcat = [TrafficClasses[name].getDataFrameIPG() for name in names] 
    
    allDF = pd.concat(framesToConcat)
    allDF = allDF.fillna(allDF.mean())
    ax = sns.boxplot(data = allDF )
    title = "IPG Boxplot: " + ' '.join(names)
    ax.set_title(title)
    ax.set_ylabel("IPG (us)")
    plt.show()

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count)) 

def main():
    global tclass_cycle_time
    parser = argparse.ArgumentParser(description='Process long term data recorded with TSN dashboard  \
    generating graphics and statistics summary for the key performance indicators.')
    
    parser.add_argument('--file', metavar='file', type = pathlib.Path,
                        help='Name of the file generated by the profishark (pcapng)', required=True)

    parser.add_argument('--start', metavar='start', type = int, default = 0,
                        help='start of the full burst, sample number of the first peak', required=False)
    
    parser.add_argument('--end', metavar='end', type = int, default = 2000,
                        help='Number of of points to use', required=False)
    
    parser.add_argument('--investigation', action="store_true",
                        help='investigate.', required=False)
    
    parser.add_argument('--fhi', metavar='fhi', type = int, default = Noframes['Hi'],
                        help='Number of TSN High frames per burst', required=False)
    
    parser.add_argument('--flow', metavar='flow', type = int, default = Noframes['Low'],
                        help='Number of TSN Low frames per burst', required=False)
    
    parser.add_argument('--frt', metavar='frt', type = int, default = Noframes['RT'],
                        help='Number of RT frames per burst', required=False)

    parser.add_argument('-c', '--cycle-time', help="Cycle time (second). Default 0.0005s (500us)", type=float, required=False, default=0.0005)


    args = parser.parse_args()
    Noframes['Hi']=args.fhi
    Noframes['Low']=args.flow
    Noframes['RT']=args.frt

    tclass_cycle_time = args.cycle_time
         
    process_pcap(args.file, args.investigation, args.start, args.end)


if __name__ == "__main__":
    main()
    