#ifndef MYPCAP_H
#define MYPCAP_H
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define EthernetSize 14
#define ipType 0x0800
#define arpType 0x0806
#define tcpType 006

struct ethernet{
    u_char Dmac[6];
    u_char Smac[6];
    uint16_t etype[2];
};

struct Ip{
    u_char length;
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
    uint8_t SequenceNumber[4];
    uint8_t AcknowledgmentNumber[4];
    uint Flag;
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
