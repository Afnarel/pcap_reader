#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

//defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define DATA_OFFSET 14

#define ICMP 1
#define TCP 6
#define UDP 17

//#define VERBOSE

// Functions prototypes
void process_file(char* filename);
void process_packets_for(pcap_t* handle);
void process_packet(u_char* packet, struct pcap_pkthdr header);
void process_ipv4_packet(u_char* packet);
int my_checksum(u_char* data, int n);

// Global vars
unsigned int nb_packets=0;   // Number of packets found
unsigned int nb_ipv4_packets=0;   // Number of IPv4 packets found


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
  else if(protocol_type == TCP || protocol_type == UDP) {

    // the only thing that differs to process the checksum of TCP and UDP packets
    // is the position of the checksum that must be set to zero for the sum :
    // It's 6 bytes into the UDP packet
    // and 16 bytes into the TCP packet.
    int offset; 

    packet += header_length; // Skip the IP header to get the UDP or TCP section
  
    int tlp_length = packet_length - header_length; // Transport Layer Protocol (UDP/TCP) length

    int checksum;

    if(protocol_type == TCP) { // TCP
      
      offset = 16; // we will need to skip 

      printf("TCP (%d)\n", protocol_type);

      struct tcphdr *tcp_hdr = (struct tcphdr *)packet;

      printf("\t\tTCP length: %d\n", tlp_length);

      checksum = htons(tcp_hdr->check);
      printf("\t\tChecksum TCP: 0x%4.4x\n", checksum);
    }
    else { // UDP

      offset = 6;

      printf("UDP (%d)\n", protocol_type);

      struct udphdr *udp_hdr = (struct udphdr *)packet;

      //int tlp_length = htons(udp_hdr->len); // Here, we could get the UDP packet length directly from struct
      printf("\t\tUDP length: %d\n", tlp_length);

      checksum = htons(udp_hdr->check);
      printf("\t\tChecksum UDP: 0x%4.4x\n", checksum);
    }

    /* ********************************************* *
     * Let's process the UDP/TCP checksum ourselves! *
     * ********************************************* */
    int somme = 0;

    /* ************* *
     * Pseudo header *
     * ************* */

    // Source IP
    somme += my_checksum((u_char* )&ip_src, 4);
    #ifdef VERBOSE
    printf("Somme: %d\n", somme);
    #endif

    // Destination IP
    somme += my_checksum((u_char* )&ip_dst, 4);
    #ifdef VERBOSE
    printf("Somme: %d\n", somme);
    #endif

    u_char zeroAndProtocol[2];
    zeroAndProtocol[0] = 0x00; // Zeros
    zeroAndProtocol[1] = protocol_type; // Protocol
    somme += my_checksum(zeroAndProtocol, 2);
    #ifdef VERBOSE
    printf("Somme: %d\n", somme);
    #endif

    // Length
    int ns_tlp_length = htons(tlp_length);
    somme += my_checksum((u_char *)&ns_tlp_length, 2);
    #ifdef VERBOSE
    printf("Somme: %d\n", somme);
    #endif


    /* ***************** *
     * TCP or UDP packet *
     * ***************** */

    // Sum everything before the checksum (source port + dest port + length) for UDP
    somme += my_checksum(packet, offset); 
    #ifdef VERBOSE
    printf("Somme: %d\n", somme);
    #endif

    packet += (offset + 2); // Skip the checksum (checksum == 0x00)

    // Sum everything after the checksum
    somme += my_checksum(packet, tlp_length - (offset + 2));
    #ifdef VERBOSE
    printf("Somme: %d\n", somme);
    #endif


    /* ****************************************** *
     * One's complement of the sum with the carry *
     * ****************************************** */

    unsigned short cs = (somme>>16) + (somme&0xffff);
    cs += (cs>>16);
    cs = ~cs;

    printf("\t\tMon Checksum : 0x%4.4x\n", cs);

    if(cs != checksum) {
      printf("=====> ERROR: checksum mismatch <=====\n");
    }

  }
}

/**
  Returns the sum of the 2-bytes (= 16-bits) words of "data".
  n is the number of bytes in data.

  For instance, if data contains 9DA9675C(16) (and n=4), this function will
  return 9DA9(16) + 675C(16) = 10505(16) = 66821(10)
*/
int my_checksum(u_char* data, int n) {
  #ifdef VERBOSE
  printf("n = %d\n", n);
  #endif
  int i, somme=0;
  for(i=1; i<n; i+=2) {
    int two_bytes = ((int)(data[i-1]) << 8) | (int)data[i];
    somme += two_bytes;
    #ifdef VERBOSE
    printf("Add: %4.4X\n", two_bytes);
    #endif
  }
  return somme;
}
