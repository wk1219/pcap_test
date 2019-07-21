#include<stdio.h>
#include"mypcap.h"
int size_ip;
int size_tcp;
int size_payload;
const u_char *payload;
void print_status(struct pcap_pkthdr* header,u_char* packet){

     struct ethernet *eth;
     struct Ip *ip;
     struct Tcp *tcp;

      eth = const_cast<ethernet*>((struct ethernet*)(packet));
      ip = const_cast<Ip*>((struct Ip*)(packet+EthernetSize));
      size_ip = IP_HL(ip)*4;
      tcp = const_cast<Tcp*>((struct Tcp*)(packet+EthernetSize+size_ip));
      size_tcp = TH_OFF(tcp)*4;

      payload = (const_cast<u_char *>(packet)+EthernetSize+size_ip+size_tcp);
      size_payload = header->caplen - size_ip - size_tcp - EthernetSize;

      printf("Destination Mac : ");
      mac_print(eth->Dmac);
      printf("Source Mac : ");
      mac_print(eth->Smac);
      if(ntohs(*(eth->etype))==(ipType)){
          printf("IPv4\n");
          printf("Source IP : ");
          ip_print(ip->Sip);
          printf("Destination IP : ");
          ip_print(ip->Dip);

          if(ntohs(*(ip->protocol)==(tcpType))){
              printf("TCP_Source Port : ");
              port_print(tcp->Sport);
              printf("TCP_Destination Port : ");
              port_print(tcp->Dport);
              printf("Payload : %d\n", size_payload);
              printf("TCP_DATA : ");
              Data(ip->totalLength, tcp);
              printf("\n");
              printf("------------------------------------\n");
          }
          else {
              printf("Protocol is not TCP\n");
              printf("------------------------------------\n");
          }
      }
      else if(ntohs(*(eth->etype))==(arpType)){
          printf("ARP\n");
      }
      else{
          printf("Source IP isn't captured\n");
          printf("Destination IP isn't captured\n");
          printf("------------------------------------\n");
      }
      printf("%u bytes captured\n", header->caplen);
      printf("------------------------------------\n");

}
void mac_print(u_char *mac){
    int cnt=1;
    for(int i=0;i<6;i++){
         printf("%02x", *mac++);
         if(cnt<=5)
         printf(":");
         cnt++;
    }
    printf("\n");
}
void ip_print(uint8_t *ip)
{
    int cnt=1;
    for(int i=0;i<4;i++){
         printf("%d", *ip++);
         if(cnt<=3)
         printf(".");
         cnt++;
    }
    printf("\n");
}

void port_print(uint8_t *port)
{
       printf("%d", *port<<8 | *(port+1));
      //  printf("%02x %02x", *ip, *(ip+1));
        printf("\n");
}
void Data(uint8_t *length, Tcp *tcp){
    if(size_payload<=0){
       printf("Data isn't exist");
    }
   else if(size_payload > 0)
      for(int i=0; i<10 && i<size_payload; i++){
          printf("%02x ", payload[i]);
      }
}
