#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
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
  int header_length = ip_hdr->ip_hl * 4;
  int packet_length = ntohs(ip_hdr->ip_len); // Get the packet length
  int protocol_type = ip_hdr->ip_p; // Get the protocol

  int ip_src = ip_hdr->ip_src.s_addr;
  int ip_dst = ip_hdr->ip_dst.s_addr;
  
  printf("Found an IPv4 packet!\n");
  printf("\tChecksum IP: %d\n", htons(ip_hdr->ip_sum));
  printf("\tIP header length: %x\n", header_length);
  printf("\tIP source: %8.8X\n", htonl(ip_src));
  printf("\tIP destination: %8.8X\n", htonl(ip_dst));
  printf("\tLength: %d\n", packet_length);
  printf("\tType: ");
  
  if(protocol_type == ICMP) {
    printf("ICMP (%d)\n", protocol_type);
  }
  else if(protocol_type == TCP) {
    printf("TCP (%d)\n", protocol_type);

    /*
        ... TODO !!!
    */
  }
  else if(protocol_type == UDP) {
    printf("UDP (%d)\n", protocol_type);
    
    packet += header_length; // Skip the IP header to get the UDP section
    struct udphdr *udp_hdr = (struct udphdr *)packet;

    int udp_length = htons(udp_hdr->len);
    printf("\t\tUDP length: %d\n", udp_length);

    int checksum = htons(udp_hdr->check);
    printf("\t\tChecksum UDP: 0x%4.4x\n", checksum);


    /* ***************************************** *
     * Let's process the UDP checksum ourselves! *
     * ***************************************** */

    // On va commencer par recreer un paquet contenant le pseudo header, le header UDP et les donnees
    u_char packet2[1024];
    int i;
    // IP Source
    u_char *ipsrc = (u_char *)&ip_src;
    for(i=0; i<4; i++) {
      packet2[i] = ipsrc[i];
    }

    // IP destination
    u_char *ipdst = (u_char *)&ip_dst;
    for(i=0; i<4; i++) {
      packet2[4+i] = ipdst[i];
    }

    // Zeros
    packet2[8] = 0x00;

    // Protocol
    packet2[9] = protocol_type;
    //packet2[9] = 0x18;

    // UDP Length
    int udp_length2 = htons(udp_length);
    u_char *udplength = (u_char *)&udp_length2;
    for(i=0; i<2; i++) {
      packet2[10+i] = udplength[i];
    }
    

    // UDP header + Data
    for(i=0; i<udp_length; i++) {
      if(i == 6 || i == 7) {
        packet2[12+i] = 0x00; // Checksum = 0
      }
      else {
        packet2[12+i] = packet[i];
      }
    }

    /*
    for(i=0; i<12+udp_length; i++) {
      printf("Mon paquet: %2.2X\n", packet2[i]);
    }
    */

    int somme = 0;
    for(i=1; i<12+udp_length; i+=2) {
      int two_bytes = ((int)(packet2[i-1]) << 8) | (int)packet2[i];
      printf("Mon paquet: %4.4X\n", two_bytes);
      somme += two_bytes;
    }


    /* // Version TCPEDIT http://tcpreplay.synfin.net/browser/trunk/src/tcpedit/checksum.c
    //int ip_hl = ip_hdr->ip_hl << 2;
    int sum = 0;

    sum += do_checksum_math((uint16_t *)&ip_src, 8);
    //sum += do_checksum_math((uint16_t *)&ip_dst, 8);
    sum += ntohs(protocol_type + udp_length);
    //sum += protocol_type + udp_length;
    sum += do_checksum_math((uint16_t *)udp_hdr, udp_length);
    printf("\t%4.4X\n", sum);
    sum = CHECKSUM_CARRY(sum);
    printf("\t%4.4X\n", sum);
    */

    /*
    // Somme des compléments à 1 des octets de l'en-tete et des donnees pris 2 par deux.
    int somme = 0;
    for(i=1; i<udp_length; i+=2) {
      //printf("%d %d\n",i,i+1);
      int two_bytes = ((int)(packet[i-1]) << 8) | (int)packet[i];
      //printf("%4.4X\n", two_bytes);
      //somme += ~two_bytes; // complement a un
      somme += two_bytes; // complement a un
    }

    // If the number of bytes in the message is odd, add a 0 at the end
    if(udp_length % 2) {

    }

    // Complement a un de la somme
    //int cs = (somme>>16) + (somme&0xffff);
    //cs += (cs>>16);
    //cs = ~cs;
    //printf("\tMon Checksum UDP: 0x%4.4x\n", cs);
    */
    unsigned short cs = (unsigned short)(~somme);

    // Dev.com
    //int cs = (~somme + 1) & 0xFFFF;
    //printf("\t\tMon Checksum UDP: 0x%4.4x\n", somme);
    //printf("\t\tMon Checksum UDP: 0x%4.4x\n", ~somme);
    printf("\t\tMon Checksum UDP: 0x%4.4x\n", cs);

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
