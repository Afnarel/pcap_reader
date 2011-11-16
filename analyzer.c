//  pcap_throughput
//
//   reads in a pcap file and outputs basic throughput statistics 

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

//defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

//------------------------------------------------------------------- 
int main(int argc, char **argv) 
{ 
  unsigned int pkt_counter=0;   // packet counter 
  unsigned long byte_counter=0; //total bytes seen in entire trace 
  unsigned long cur_counter=0; //counter for current 1-second interval 
  unsigned long current_ts=0; //current timestamp 
 
  //temporary packet buffers 
  struct pcap_pkthdr header; // The header that pcap gives us 
  const u_char *packet; // The actual packet 
  
  //check command line arguments 
  if (argc < 2) { 
    fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]); 
    exit(1); 
  } 
  
  //-------- Begin Main Packet Processing Loop ------------------- 
  //loop through each pcap file in command line args 
  int fnum;
  for (fnum=1; fnum < argc; fnum++) {  
 
    //----------------- 
    //open the pcap file 
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well 
    handle = pcap_open_offline(argv[fnum], errbuf);   //call pcap library function 
 
    if (handle == NULL) { 
      fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[fnum], errbuf); 
      return(2); 
    } 
 
    //----------------- 
    //begin processing the packets in this particular file, one at a time 
 
    while ( (packet = pcap_next(handle,&header)) ) { 
      // header contains information about the packet (e.g. timestamp) 
      u_char *pkt_ptr = (u_char *)packet; //cast a pointer to the packet data 
      
      //parse the first (ethernet) header, grabbing the type field 
      int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13]; 
      int ether_offset = 0; 
 
      if (ether_type == ETHER_TYPE_IP) //most common 
        ether_offset = 14; 
      else if (ether_type == ETHER_TYPE_8021Q) //my traces have this 
         ether_offset = 18; 
      else 
         fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type); 
 
      //parse the IP header 
      pkt_ptr += ether_offset;  //skip past the Ethernet II header 
      struct ip *ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure 
 
      int packet_length = ntohs(ip_hdr->ip_len); 
 
      //check to see if the next second has started, for statistics purposes 
      if (current_ts == 0) {  //this takes care of the very first packet seen 
         current_ts = header.ts.tv_sec; 
      } else if (header.ts.tv_sec > current_ts) { 
         printf("%lu KBps\n", cur_counter/1000); //print 
         cur_counter = 0; //reset counters 
         current_ts = header.ts.tv_sec; //update time interval 
      } 
 
      cur_counter += packet_length; 
      byte_counter += packet_length; //byte counter update 
      pkt_counter++; //increment number of packets seen 
 
    } //end internal loop for reading packets (all in one file) 
 
    pcap_close(handle);  //close the pcap file 
 
  } //end for loop through each command line argument 
  //---------- Done with Main Packet Processing Loop --------------  
 
  //output some statistics about the whole trace 
  byte_counter /= 1e6;  //convert to MB to make easier to read 
 
  printf("Processed %d packets and %lu MBytes, in %d files\n", pkt_counter, byte_counter, argc-1);
  return 0; //done
} //end of main() function
