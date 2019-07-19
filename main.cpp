#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6

/*Ethernet header*/
typedef struct ether_header
{
	uint8_t  eth_dst[ETHER_ADDR_LEN]; 	//6byte
	uint8_t  eth_src[ETHER_ADDR_LEN];	//6byte
	uint16_t eth_type;			//2byte
}ETHER_HDR;

typedef struct ip_header
{
	uint8_t ip_hdr_len : 4;
	uint8_t ip_version : 4;			//4bit
	uint8_t ip_tos;
	uint16_t total_len;			//2byte
	uint16_t identifi;			//2byte
	uint8_t ip_off : 5;
						//5bit
	uint8_t ip_rf : 1;			//reserved fragment flag
	uint8_t ip_mf : 1;
	uint8_t ip_df : 1;			//don't fragment flag
	uint8_t ip_off2;			//mask for fragmenting bits

	uint8_t ip_TTL	;			//1byte
	uint8_t ip_proto;			//1byte
	uint16_t ip_hdr_CheckSum;		//2byte
	uint8_t ip_src[4];			//4byte
	uint8_t ip_dst[4];			//4byte
}IP_HDR;

typedef struct tcp_header
{
	uint16_t tcp_sport;
	uint16_t tcp_dport;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	//little endian 
	uint8_t data_reserved :4;
	uint8_t data_offset :4;
	uint8_t fin : 1;
	uint8_t syn : 1;
	uint8_t rst : 1;
	uint8_t psh : 1;
	uint8_t ack : 1;
	uint8_t urg : 1;
	uint8_t ecn : 1;
	uint8_t cwr : 1;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_Pointer;
}TCP_HDR;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void ExtractPkt(int, const u_char*);
void Print_ether_header(int,const u_char*);
void Extract_Ip_header(int,const u_char*);
void Extract_Tcp_Pkt(int,const u_char*);
void Extract_port(int,const u_char*);
void Extract_Tcp_data(int,const u_char*);

ETHER_HDR* ether_hdr;
IP_HDR* ip_hdr;
TCP_HDR* tcp_hdr;

const u_char* data;
const u_char* datacheck;

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    ExtractPkt(header->caplen,packet);
  }

  pcap_close(handle);
  return 0;
}

void ExtractPkt(int size, const u_char* packet)
{
	ether_hdr = (ETHER_HDR *)packet;
	
	if(ntohs(ether_hdr->eth_type) == 0x0800 )
	{
		//ip header
		ip_hdr=(IP_HDR*)(packet + sizeof(ETHER_HDR));
	
		switch(ip_hdr->ip_proto)
		{
			case 6: //TCP Protocol
			Extract_Tcp_Pkt(size,packet);
			break;
			default:
			break;
		}
	}
	
}

void Extract_Ip_header(int size,const u_char* packet)
{
	uint16_t ip_len;
        ip_hdr=(IP_HDR*)(packet+sizeof(ETHER_HDR));
        ip_len=ip_hdr->ip_hdr_len*4;

	Print_ether_header(size,packet);	

        printf("Src IP address : %d.%d.%d.%d\n",ip_hdr->ip_src[0],ip_hdr->ip_src[1],ip_hdr->ip_src[2],ip_hdr->ip_src[3]);
        printf("Dst IP Address : %d.%d.%d.%d\n",ip_hdr->ip_dst[0],ip_hdr->ip_dst[1],ip_hdr->ip_dst[2],ip_hdr->ip_dst[3]);
}

void Extract_Tcp_Pkt(int size,const u_char* packet)
{
	int ip_len;
	int tcp_len;

	ip_hdr=(IP_HDR*)(packet+sizeof(ETHER_HDR));
	ip_len=ip_hdr->ip_hdr_len*4;
	tcp_hdr=(TCP_HDR*)(packet+ip_len+sizeof(ETHER_HDR));
	tcp_len=tcp_hdr->data_offset*4;

    printf("======================================================================\n");
	Extract_Ip_header(size,packet);
	Extract_port(size,packet);
	Extract_Tcp_data(size,packet);
	printf("======================================================================\n");
}

void Extract_Tcp_data(int data_size,const u_char* packet)
{
        int ip_len=0;
        int tcp_len=0;
	int data_len=0;

        ip_hdr=(IP_HDR*)(packet+sizeof(ETHER_HDR));
        ip_len=ip_hdr->ip_hdr_len*4;
        tcp_hdr=(TCP_HDR*)(packet+ip_len+sizeof(ETHER_HDR));
        tcp_len=tcp_hdr->data_offset*4;

	if((ip_len+tcp_len+sizeof(ETHER_HDR))== data_size)
		return;

	data=(packet+ip_len+tcp_len+sizeof(ETHER_HDR));
	data_len=data_size-sizeof(ETHER_HDR)-ip_len-tcp_len;

	printf("Tcp payload : ");
	for(int i=0;i<data_len;i++)
	{
		printf("0x%x ",data[i]);
		if(i==9)break;
	}
	printf("\n");
}

void Extract_port(int size,const u_char* packet)
{
	uint16_t ip_len;
        uint16_t tcp_len;
        ip_hdr=(IP_HDR*)(packet+sizeof(ETHER_HDR));
        ip_len=ip_hdr->ip_hdr_len*4;
        tcp_hdr=(TCP_HDR*)(packet+ip_len+sizeof(ETHER_HDR));
	printf("Src port : %d\n",ntohs(tcp_hdr->tcp_sport));
	printf("Dst port : %d\n",ntohs(tcp_hdr->tcp_dport));

}

void Print_ether_header(int size,const u_char* packet)
{
	ether_hdr=(ETHER_HDR*)packet;
	printf("Src Mac address : %02x:%02x:%02x:%02x:%02x:%02x\n",ether_hdr->eth_src[0],ether_hdr->eth_src[1],ether_hdr->eth_src[2],ether_hdr->eth_src[3],ether_hdr->eth_src[4],ether_hdr->eth_src[5]);
        printf("Dst Mac address : %02x:%02x:%02x:%02x:%02x:%02x\n",ether_hdr->eth_dst[0],ether_hdr->eth_dst[1],ether_hdr->eth_dst[2],ether_hdr->eth_dst[3],ether_hdr->eth_dst[4],ether_hdr->eth_dst[5]);
}


