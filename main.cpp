#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include<stdlib.h>

#define INFOLEN 256
#define ARP_PACKET_LEN (sizeof(struct ether_header) + sizeof(struct ether_arp))

char INFO[INFOLEN];

void usage() {
  
  printf("syntax: tcp_block <interface>\n");
  printf("sample: tcp_block wlan0\n");
  exit(-1);

}

bool get_local_mac(const char *name) {
	snprintf(INFO, INFOLEN, "/sys/class/net/%s/address", name);
	FILE *fp = fopen(INFO, "r");
  if (!fp) return false;

	fgets(INFO, INFOLEN, fp);
	INFO[strcspn(INFO, "\r\n")] = '\0';
	fclose(fp);
	return true;
}

void tcp_block(pcap_t *handle, uint8_t *my_mac, struct ether_header *ETH, struct tcphdr *TCP, struct ip *IP, int datalen, uint8_t flags, bool isforward){
  uint8_t *DATA_NEW=(uint8_t *)malloc(9);
  struct ether_header *ETH_NEW=(struct ether_header *)malloc(sizeof(struct ether_header) + 1);
  struct tcphdr *TCP_NEW=(struct tcphdr *)malloc(sizeof(struct tcphdr) + 1); 
  struct ip *IP_NEW=(struct ip *)malloc(sizeof(struct ip) + 1);
 
  memcpy(DATA_NEW,"warning",sizeof("warning"));

  ETH_NEW->ether_type = htons(ETHERTYPE_IP);
  memcpy(ETH_NEW->ether_shost, my_mac, 6);
  
  IP_NEW->ip_hl=5;
  IP_NEW->ip_v=4;
  IP_NEW->ip_tos=0;

  if(flags==TH_FIN|TH_ACK) IP_NEW->ip_len = htons(40 + sizeof(DATA_NEW));
  else IP_NEW->ip_len=htons(40);

  IP_NEW->ip_id = htons(0xAAAA);
	IP_NEW->ip_off = 0;
	IP_NEW->ip_ttl = 255;
	IP_NEW->ip_p = IPPROTO_TCP;
  IP_NEW->ip_sum = 0;

  if (isforward){
		memcpy(ETH_NEW->ether_dhost, ETH->ether_dhost, 6);

    TCP_NEW->th_sport = TCP->th_sport;
		TCP_NEW->th_dport = TCP->th_dport;
		TCP_NEW->th_seq = ntohl(htonl(TCP->th_seq) + datalen);
		TCP_NEW->th_ack = TCP->th_ack;

		IP_NEW->ip_src = IP->ip_src;
		IP_NEW->ip_dst = IP->ip_dst;
	}
	else{
		memcpy(ETH_NEW->ether_dhost, ETH->ether_shost, 6);

    TCP_NEW->th_sport = TCP->th_dport;
		TCP_NEW->th_dport = TCP->th_sport;
		TCP_NEW->th_seq = TCP->th_ack;
		TCP_NEW->th_ack = ntohl(htonl(TCP->th_seq) + datalen);
    
		IP_NEW->ip_src = IP->ip_dst;
		IP_NEW->ip_dst = IP->ip_src;
  }

  TCP_NEW->th_off = 5;
	TCP_NEW->th_flags = flags;
	TCP_NEW->th_win = 0;
	TCP_NEW->th_sum = 0;
  TCP_NEW->th_urp = 0;

  //IP checksum
	int ip_cal = 0;
	uint16_t *tmp = (uint16_t *)IP_NEW;
	for (int i = 0; i < 10; i++)ip_cal += ntohs(tmp[i]);
	if (ip_cal > 0xFFFF) ip_cal = (ip_cal / 0x10000) + (ip_cal & 0xFFFF);

	IP_NEW->ip_sum = htons(ip_cal) ^ 0xFFFF;

	//TCP checksum
	int tcp_cal = 0;
	for (int i = 6; i < 10; i++) tcp_cal += ntohs(tmp[i]);
	tcp_cal += IPPROTO_TCP;
	if (flags == TH_FIN + TH_ACK) tcp_cal += 20 + sizeof(DATA_NEW);
	else	tcp_cal += 20;

	tmp = (uint16_t *)TCP_NEW;
	for (int i = 0; i < 10; i++) tcp_cal+= ntohs(tmp[i]);

	if (flags == TH_FIN | TH_ACK){  //FIN
		tmp = (uint16_t *)DATA_NEW;
		for (int i = 0; i < sizeof(DATA_NEW) / 2; i++) tcp_cal += ntohs(tmp[i]);

		if (sizeof(DATA_NEW) % 2) tcp_cal += ntohs(DATA_NEW[sizeof(DATA_NEW)-1] << 8);
	}

	if (tcp_cal> 0xFFFF)	tcp_cal = (tcp_cal / 0x10000) + (tcp_cal & 0xFFFF);
	TCP_NEW->th_sum = htons(tcp_cal) ^ 0xFFFF;

  uint8_t *tcp_flags = (uint8_t *)malloc(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + 8);
	tcp_flags = (uint8_t *)ETH_NEW;
	memcpy(tcp_flags + sizeof(struct ether_header), IP_NEW, sizeof(struct ip));
	memcpy(tcp_flags + sizeof(struct ether_header) + sizeof(struct ip), TCP_NEW, sizeof(struct tcphdr));

	if (flags == TH_FIN | TH_ACK){
		memcpy(tcp_flags + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr), DATA_NEW, sizeof(DATA_NEW));
		if (pcap_inject(handle, tcp_flags, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(DATA_NEW)) == -1){
			fprintf(stderr, "Error : %s\n", pcap_geterr(handle));
      free(tcp_flags);
      free(DATA_NEW);
      free(ETH_NEW);
      free(TCP_NEW);
      free(IP_NEW);
			exit(-1);
		}
	}
	else{
		if (pcap_inject(handle, tcp_flags, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr)) == -1){
			fprintf(stderr, "Error : %s\n", pcap_geterr(handle));
      free(tcp_flags);
      free(DATA_NEW);
      free(ETH_NEW);
      free(TCP_NEW);
      free(IP_NEW);
			exit(-1);
		}
	}

	if (flags == TH_FIN + TH_ACK) printf("Sent TCP FIN!\n");
  else printf("Sent TCP RST!\n");

  free(tcp_flags);
  free(DATA_NEW);
  free(ETH_NEW);
  free(TCP_NEW);
  free(IP_NEW);
}

int main(int argc, char* argv[]) {
  if(argc!=2) usage();
  char* dev = argv[1];

  if(!get_local_mac(dev)){
    printf("Local MAC error: %s\n",INFO);
    return -1;
  }
  uint8_t my_mac[6];
  memcpy(my_mac,INFO,sizeof(my_mac));

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  const char http_type[6][9] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS "};
  const int http_typelen[6] = {4, 5, 5, 4, 7, 8};

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    struct ether_header *ETH=(struct ether_header *)packet;
	
	  if(ntohs(ETH->ether_type)==ETHERTYPE_IP){
      packet+=sizeof(struct ether_header);
		  struct ip *IP=(struct ip *)packet;

		  if(IP->ip_p==IPPROTO_TCP){
			  packet+=IP->ip_hl*4;
			  struct tcphdr *TCP=(struct tcphdr *)packet;

			  u_int8_t *DATA=(u_int8_t *)((u_int8_t *)TCP+TCP->doff*4);
			  int data_len=ntohs(IP->ip_len)-IP->ip_hl*4-TCP->doff*4;
        if(data_len==0)continue;

        for(int x=0;x<6;x++){
					if (memcmp(DATA, http_type[x], http_typelen[x]) == 0){
						printf("HTTP found : %s\n", http_type[x]);
            //여기까지
            tcp_block(handle,my_mac,ETH,TCP,IP,data_len,TH_RST | TH_ACK,true);
            tcp_block(handle,my_mac,ETH,TCP,IP,data_len,TH_RST | TH_ACK,false);
            break;
					}
        }

		  }

	  }

  }

  pcap_close(handle);
  return 0;
}