#ifndef MYPCAP_H
#define MYPCAP_H
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define EthernetSize 14 // Ethenet Header Size
#define ipType 0x0800   // IP TYPE 0x0800
#define arpType 0x0806  // ARP TYPE 0x0806
#define tcpType 0x0006  // TCP TYPE 0x0006

struct ethernet{
    uint8_t Dmac[6];
    uint8_t Smac[6];
    uint16_t etype;
};

struct Ip{
    uint8_t length;
    uint8_t seviceField;
    uint8_t totalLength[2];
    uint16_t Id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol[1];
    uint16_t checksum;
    uint8_t Sip[4];
    uint8_t Dip[4];
};
#define IP_HL(ip)   (((ip)->length)&0x0f)
struct Tcp{
    uint8_t Sport[2];
    uint8_t Dport[2];
    uint32_t SequenceNumber;
    uint32_t AcknowledgmentNumber;
    uint8_t Flag;
    uint8_t WindowSize[2];
    uint8_t checksum[2];
    uint8_t urgent[2];
};
#define TH_OFF(tcp)  (((tcp)->Flag & 0x0f0)>>4)
void mac_print(u_char *eth);
void ip_print(uint8_t *ip);
void port_print(uint8_t *ip);
void Data(uint8_t *length, Tcp * tcp);
void print_status(struct pcap_pkthdr* header, u_char* packet);

#endif // MYPCAP_H
