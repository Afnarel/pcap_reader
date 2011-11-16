#include <stdio.h>
#include <pcap.h>
#include <sys/types.h>

int
main(int argc, char *argv[])
{
    char           *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t         *handle;
    const u_char   *packet;     /* The actual packet */
    struct pcap_pkthdr header;  /* The header that pcap gives us */

    //dev = pcap_lookupdev(errbuf);
    dev = "wlan0";
    if (dev == NULL) {
        fprintf(stderr,
                "Couldn't find default device (may be a permission issue): %s\n",
                errbuf);
        return (2);
    }
    printf("Sniffing on device: %s\n", dev);
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }
    while (1) {
        /* Grab a packet */
        packet = pcap_next(handle, &header);
        /* Application-specific code: here, we do something with the packet */
        int ether_type = ((int)(packet[12]) << 8) | (int)packet[13]; 
        printf("%d", ether_type);
    }
    /* And close the session */
    pcap_close(handle);

    return (0);
}
