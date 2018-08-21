/*
 * netlog.c
 *
 *  Created on: Aug 17, 2018
 *      Author: Thiago Cavalcante, with some information got from www.tcpdump.org/
 */

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

void packet_handler(
  u_char *args,
  const struct pcap_pkthdr *header,
  const u_char *packet
);
void packet_handler2(
  u_char *args,
  const struct pcap_pkthdr *header,
  const u_char *packet
);
void packet_handler3(
  u_char *args,
  const struct pcap_pkthdr *header,
  const u_char *packet
);
void print_packet_info(struct pcap_pkthdr packet_header);
void help();

int main(int argc, char *argv[]){
  char *device; /* device name (wlan0, enp0s25, eth0) */
  char ip[13]; /* IP address */
  char subnet_mask[13]; /* Subnet mask */
  uint32_t ip_raw; /* IP address as integer */
  uint32_t subnet_mask_raw; /* Subnet mask as integer */
  int lookup_return_code, i, c;
  char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
  struct in_addr address; /* Used for both ip & subnet */
  pcap_t *handle;
  int timeout_limit = 10000; /* In milliseconds */
  char filter_exp[] = ""; /* filter expression */
  struct bpf_program filter;
  const u_char *packet;
  struct pcap_pkthdr packet_header;

  opterr = 0;

  while((c = getopt (argc, argv, "d:sf:lith")) != -1)
    switch(c)
    {
      case 'd':
    	device = optarg; /* Got from command line */
    	printf("Device: %s\n", device);
    	continue;
      case 's':
        /* Find a device */
        device = pcap_lookupdev(error_buffer); /* Look up for devices */
        if(device == NULL)
        {
          printf("%s\n", error_buffer);
          return 1;
        }
        else
          printf("Device: %s\n", device);
        continue;
      case 'f':
    	strcpy(filter_exp, optarg);
        if(pcap_lookupnet(device, &ip_raw, &subnet_mask_raw, error_buffer) == -1)
        {
          printf("Could not get information for device: %s\n", device);
          ip_raw = 0;
          subnet_mask_raw = 0;
        }
        handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
        if(handle == NULL)
        {
          printf("Could not open %s - %s\n", device, error_buffer);
          return 2;
        }
        if(pcap_compile(handle, &filter, filter_exp, 0, ip_raw) == -1)
        {
          printf("Bad filter - %s\n", pcap_geterr(handle));
          return 2;
        }
        if(pcap_setfilter(handle, &filter) == -1)
        {
          printf("Error setting filter - %s\n", pcap_geterr(handle));
          return 2;
        }
        /* Attempt to capture one packet. If there is no network traffic
           and the timeout is reached, it will return NULL */
        packet = pcap_next(handle, &packet_header);
        if(packet == NULL)
        {
          printf("No packet found.\n");
          return 2;
        }
        /* Function to output some info */
        print_packet_info(packet_header);

        pcap_loop(handle, 1, packet_handler, NULL);
        pcap_close(handle);
        break;
      case 'l':
        /* Open device for live capture */
        handle = pcap_open_live(
                device,
                BUFSIZ,
                0,
                timeout_limit,
                error_buffer
            );
        if(handle == NULL)
        {
          fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
          return 2;
    	}

    	pcap_loop(handle, 0, packet_handler, NULL);
    	pcap_close(handle);
        break;
      case 'i':
        /* Get device info */
   	    lookup_return_code = pcap_lookupnet(
   	    device,
      	&ip_raw,
      	&subnet_mask_raw,
      	error_buffer
      	);
      	if(lookup_return_code == -1)
      	{
      	  printf("%s\n", error_buffer);
      	  return 1;
      	}
      	/* Get ip in decimal form 4 octets (32 bits) ipv4*/
      	address.s_addr = ip_raw;
      	strcpy(ip, inet_ntoa(address));
      	if(ip == NULL)
      	{
      	  perror("inet_ntoa"); /* print error */
      	  return 1;
      	}
      	/* Get subnet in decimal form 4 octets (32 bits) ipv4 */
      	address.s_addr = subnet_mask_raw;
      	strcpy(subnet_mask, inet_ntoa(address));
      	if(subnet_mask == NULL)
      	{
      	  perror("inet_ntoa");
      	  return 1;
      	}

      	printf("IP address: %s\n", ip);
      	printf("Subnet mask: %s\n", subnet_mask);
        break;
      case 't':
        /* Open device for live capture */
        handle = pcap_open_live(
                device,
                BUFSIZ,
                0,
                timeout_limit,
                error_buffer
            );
        if(handle == NULL)
        {
          fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
          return 2;
    	}

    	pcap_loop(handle, 0, packet_handler2, NULL);
    	pcap_close(handle);
        break;
      case 'h':
        help();
        break;
      case '?':
        if(optopt == 'd')
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        else if(optopt == 'f')
            fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        else if(isprint (optopt))
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf(stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
        abort();
    }

  for(i = optind; i < argc; i++)
    printf ("Non-option argument %s\n", argv[i]);

  return 0;
}

/* Finds the payload of a TCP/IP packet */
void packet_handler(
  u_char *args,
  const struct pcap_pkthdr *header,
  const u_char *packet
)
{
  /* Pointers to start point of various headers */
  const u_char *ip_header;
  const u_char *tcp_header;
  const u_char *payload;

  /* Header lengths in bytes */
  int ethernet_header_length = 14; /* Doesn't change */
  int ip_header_length;
  int tcp_header_length;
  int payload_length;

  /* First, lets make sure we have an IP packet */
  struct ether_header *eth_header;
  eth_header = (struct ether_header *) packet;
  if(ntohs(eth_header->ether_type) != ETHERTYPE_IP)
  {
    printf("Not an IP packet. Skipping...\n\n");
    return;
  }

  /* The total packet length, including all headers
     and the data payload is stored in
     header->len and header->caplen. Caplen is
     the amount actually available, and len is the
     total packet length even if it is larger
     than what we currently have captured. If the snapshot
     length set with pcap_open_live() is too small, you may
     not have the whole packet. */
  printf("Total packet available: %d bytes\n", header->caplen);
  printf("Expected packet size: %d bytes\n", header->len);

  /* Find start of IP header */
  ip_header = packet + ethernet_header_length;
  /* The second-half of the first byte in ip_header
     contains the IP header length (IHL). */
  ip_header_length = ((*ip_header) & 0x0F);
  /* The IHL is number of 32-bit segments. Multiply
     by four to get a byte count for pointer arithmetic */
  ip_header_length = ip_header_length * 4;
  printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

  /* Now that we know where the IP header is, we can
     inspect the IP header for a protocol number to
     make sure it is TCP before going any further.
     Protocol is always the 10th byte of the IP header */
  u_char protocol = *(ip_header + 9);
  if(protocol != IPPROTO_TCP)
  {
    printf("Not a TCP packet. Skipping...\n\n");
    return;
  }

  /* Add the ethernet and ip header length to the start of the packet
     to find the beginning of the TCP header */
  tcp_header = packet + ethernet_header_length + ip_header_length;
  /* TCP header length is stored in the first half
     of the 12th byte in the TCP header. Because we only want
     the value of the top half of the byte, we have to shift it
     down to the bottom half otherwise it is using the most
     significant bits instead of the least significant bits */
  tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
  /* The TCP header length stored in those 4 bits represents
     how many 32-bit words there are in the header, just like
     the IP header length. We multiply by four again to get a
     byte count. */
  tcp_header_length = tcp_header_length * 4;
  printf("TCP header length in bytes: %d\n", tcp_header_length);

  /* Add up all the header sizes to find the payload offset */
  int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
  printf("Size of all headers combined: %d bytes\n", total_headers_size);
  payload_length = header->caplen -
      (ethernet_header_length + ip_header_length + tcp_header_length);
  printf("Payload size: %d bytes\n", payload_length);
  payload = packet + total_headers_size;
  printf("Memory address where payload begins: %p\n\n", payload);

  /* Print payload in ASCII */
  if(payload_length > 0)
  {
    const u_char *temp_pointer = payload;
    int byte_count = 0;
    printf("-------------------------------Payload-------------------------------\n\n");
    while (byte_count++ < payload_length) {
      printf("%c", *temp_pointer);
      temp_pointer++;
    }
    printf("\n\n---------------------------------------------------------------------\n");
  }


  return;
}

/* Find if a packet if IP, ARP or Reverse ARP */
void packet_handler2(
  u_char *args,
  const struct pcap_pkthdr *header,
  const u_char *packet
)
{
  struct ether_header *eth_header;
  /* The packet is larger than the ether_header struct,
     but we just want to look at the first part of the packet
     that contains the header. We force the compiler
     to treat the pointer to the packet as just a pointer
     to the ether_header. The data payload of the packet comes
     after the headers. Different packet types have different header
     lengths though, but the ethernet header is always the same (14 bytes) */
  eth_header = (struct ether_header *) packet;

  if(ntohs(eth_header->ether_type) == ETHERTYPE_IP)
  {
    printf("IP\n");
  }
  else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
  {
    printf("ARP\n");
  }
  else if(ntohs(eth_header->ether_type) == ETHERTYPE_REVARP)
  {
    printf("Reverse ARP\n");
  }
  else if(ntohs(eth_header->ether_type) == ETHERTYPE_IPV6)
  {
    printf("IPV6\n");
  }
  else if(ntohs(eth_header->ether_type) == ETHERTYPE_LOOPBACK)
  {
    printf("Loop back\n");
  }
}

/* Show some packet infos */
void packet_handler3(
  u_char *args,
  const struct pcap_pkthdr *packet_header,
  const u_char *packet_body
)
{
  print_packet_info(*packet_header);
  return;
}

void print_packet_info(struct pcap_pkthdr packet_header)
{
  printf("Packet capture length: %d\n", packet_header.caplen);
  printf("Packet total length %d\n", packet_header.len);
}

void help()
{
  printf("\n");
  printf("* * *           NETLog          * * *\n");
  printf("Usage:                       Purpose:\n\n");
  printf("./netlog [-h]                show help\n");
  printf("./netlog       ...                               \n\n");
  printf("Options:\n\n");
  printf("-d                           set the device to be analyzed (wlan0, enp0s25, eth0).\n");
  printf("-s                           search for devices (wlan0, enp0s25, eth0).\n");
  printf("-f                           filter packets (\"port 80\", \"host 8.8.8.8\").\n");
  printf("-l                           live capture in a loop.\n");
  printf("-i                           get the device info (host address and subnet mask).\n");
  printf("-t                           determine the packet type (IP, ARP, Reverse ARP).\n");
  exit(0);
}
