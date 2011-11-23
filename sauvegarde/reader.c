#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

//defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define DATA_OFFSET 14

#define ICMP 1
#define TCP 6
#define UDP 17

// Functions prototypes
void process_file(char* filename);
void process_packets_for(pcap_t* handle);
void process_packet(u_char* packet, struct pcap_pkthdr header);
void process_ipv4_packet(u_char* packet);

// Global vars
unsigned int nb_packets=0;   // Number of packets found
unsigned int nb_ipv4_packets=0;   // Number of IPv4 packets found
unsigned int nb_ipv6_packets=0;   // Number of IPv4 packets found

/* // Useless
unsigned long byte_counter=0; //total bytes seen in entire trace 
unsigned long cur_counter=0; //counter for current 1-second interval 
unsigned long current_ts=0; //current timestamp
*/

int main(int argc, char* argv[]) {

  // Read command line arguments to get the file name
  if (argc < 2) { 
    fprintf(stderr, "Usage: %s data.cap\n", argv[0]); 
    exit(EXIT_FAILURE);
  }

  process_file(argv[1]);

  printf("Total number of packets found: %u\n", nb_packets);
  printf("Number of IPv4 packets found: %u\n", nb_ipv4_packets);

  return EXIT_SUCCESS;
}

/**
  Opens a capture file
  and get a handle
 */
void process_file(char* filename) {
  //open the capture file 
  pcap_t *handle; 
  char errbuf[PCAP_ERRBUF_SIZE]; // Create a buffer to store the errors
  handle = pcap_open_offline(filename, errbuf); // Open the capture file

  // If an error occured while opening, the file, abort
  if (handle == NULL) { 
    fprintf(stderr,"Couldn't open capture file %s: %s\n", filename, errbuf); 
    exit(-1); 
  }

  // Process packets
  process_packets_for(handle);

  pcap_close(handle);  //close the handle
}

/**
  Process the packets
 */
void process_packets_for(pcap_t* handle) {

  u_char* packet; // Packet
  struct pcap_pkthdr header; // Header
  while ( (packet = (u_char *)pcap_next(handle,&header)) ) { // Get the packet

    process_packet(packet, header);

  }

}

void process_packet(u_char* packet, struct pcap_pkthdr header) {

  // header contains information about the packet (e.g. timestamp) 
  //u_char *pkt_ptr = (u_char *)packet; //cast a pointer to the packet data 

  // Get the "Protocol type" field (12th & 13th bytes)
  int ether_type = ((int)(packet[12]) << 8) | (int)packet[13]; 

  if (ether_type == ETHER_TYPE_IP) { // If we found an IPv4 packet
    nb_ipv4_packets++;
    process_ipv4_packet(packet);
  }

  nb_packets++;
}

void process_ipv4_packet(u_char* packet) {
  packet += DATA_OFFSET; // Skip until we find the data section

  struct ip *ip_hdr = (struct ip *)packet; // Get the IP header
  int packet_length = ntohs(ip_hdr->ip_len); // Get the packet
  int protocol_type = ip_hdr->ip_p; // Get the protocol
  
  printf("Found an IPv4 packet!\n");
  printf("\tlength: %d\n", packet_length);
  printf("\tType: ");
  
  if(protocol_type == ICMP) {
    printf("ICMP\n");
  }
  else if(protocol_type == TCP) {
    printf("TCP\n");
  }
  else if(protocol_type == UDP) {
    printf("UDP\n");
  }
}
/*
   else {
   fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type);
   }
 */

/*
//parse the IP header
packet += ether_offset;  //skip past the Ethernet II header 
struct ip *ip_hdr = (struct ip *)packet; //point to an IP header structure 

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
 */
