#ifndef HEADERS_H
#define HEADERS_H
#pragma comment(lib,"ws2_32.lib")
#pragma pack(push,1)
//以1字节方式字节对齐。防止它改变头部结构
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <pcap.h>
#include "stdio.h"
#include "windows.h"
extern char *myIP;
extern char *myMAC;
extern char *myPhoneMAC;

struct MAC{
	unsigned char addr[6];
};

struct MACHeader{
	MAC dest_MAC;
	MAC src_MAC;
	unsigned short protocol_type;
};
#define MAC_PROTOCOL_TYPE_IP 0x0008
#define MAC_PROTOCOL_TYPE_ARP 0x0608

struct IPHeader{
	unsigned char ver_hlen;
	unsigned char tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int sourceIP;
	unsigned int destIP;
};
struct ICMPHeader{
	unsigned char type;
	unsigned char code;
	unsigned short cksum;
	unsigned short id;
	unsigned short seq;
};
struct ARPHeader{
	u_short hardware_type;
	u_short protocol_type;
	u_char hardware_size;
	u_char protocol_size;
	u_short opcode;
	MAC MAC_sender;
	unsigned long IP_sender;
	MAC MAC_target;
	unsigned long IP_target;

};
class Host{
public:
	MAC mac;
	unsigned int IP;
	unsigned int port_number;
	unsigned int * port_list;
};

#define ARP_OP_REQUEST 0x0100
#define ARP_OP_REPLY   0x0200
#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define getIP(strIP) (inet_addr((strIP)))
void SetColor(int ForgC);
MAC getMAC(char * strMAC);
void MAC_copy(MAC src,MAC dst);
char * package_Receive(pcap_t * fp,pcap_pkthdr &header);
void Package_Change_srcMAC(unsigned char * pBuf,MAC newMAC);
void Package_Change_srcIP(unsigned char * pBuf,unsigned long newIP);
void MAC_MakePackage(char * pBuf,MAC srcMAC,MAC dstMAC,u_short protocol_type);
void IP_MakePackage(char * pBuf,unsigned int package_size,unsigned long srcIP,unsigned long dstIP,u_short id);
char * ICMP_MakePackage(unsigned long srcIP,unsigned long dstIP,MAC srcMAC,MAC dstMAC,u_short id);
void ARP_MakePackage(char * pData,u_int opcode,MAC srcMAC,MAC dstMAC,unsigned long srcIP,unsigned long dstIP);
USHORT CheckSum(USHORT * pUShort,int size);
void SetFilter(pcap_t * fp,char * str);
bool MAC_equal(MAC src1,MAC src2);
void MAC_toString(MAC mac,char * str);
void IP_toString(unsigned long IP,char * str);
void send_raw_package(pcap_t * fp,u_char * packet,int packet_size,int times);

class HostManager{
public:
	unsigned int host_number;
	Host * host_list;
	HostManager(){
		host_number=0;
		host_list=new Host[500];
	}
	void newHost(Host nh){
		host_list[host_number]=nh;
	}
	bool newHost(MAC mac,unsigned int IP){
		if(host_number>=500)return 0;
		host_list[host_number].IP=IP;
		host_list[host_number].mac=mac;
		host_number++;
		return 1;
	}
	Host getHost(unsigned int idx){
		return host_list[idx];
	}
	int getHostByIP(unsigned long targetIP){
		for(unsigned int i=0;i<host_number;i++){
			if(host_list[i].IP==targetIP){
				return i;
			}
		}
		return -1;
	}
	int getHostByMAC(MAC targetMAC){
		for(unsigned int i=0;i<host_number;i++){
			if(MAC_equal((host_list[i].mac),targetMAC)){
				return i;
			}
		}
		return -1;
	}
	void ARP_read(char * pData){
		unsigned int package_size=sizeof(MACHeader)+sizeof(ARPHeader);
		MACHeader * pMACHeader=(MACHeader *)(pData);
		ARPHeader * pARPHeader=(ARPHeader *)(pData+sizeof(MACHeader));
		if(getHostByIP(pARPHeader->IP_sender)<0){
			newHost(pARPHeader->MAC_sender,pARPHeader->IP_sender);
			char tmp_ip[20];
			IP_toString(pARPHeader->IP_sender,tmp_ip);
			printf(".");
			//printf("DiscoverHost--> %s\n",tmp_ip);
		}
	}
	int getGateWay(){
		for(unsigned int i=0;i<host_number;i++){
			if(host_list[i].IP>>24==1)return i;
		}
		return -1;
	}
	void lookClearDHCP(){
		int host_gt=getGateWay();
		int new_array_i=0;
		for(unsigned int i=0;i<host_number;i++){
			if((host_gt==i) || (!MAC_equal(host_list[host_gt].mac,host_list[i].mac))){
				host_list[new_array_i++]=host_list[i];
			}
		}
		host_number=new_array_i;
	}
	unsigned int selectHost(char * hint){
		char tmp_ip[20],tmp_mac[20];

		SetColor(2);
		printf("The hosts are listed below:\n");
		SetColor(5);
		for(unsigned int i=0;i<host_number;i++){
			MAC_toString(host_list[i].mac,tmp_mac);
			IP_toString(host_list[i].IP,tmp_ip);

			printf("%03d :  %s  :  %s\n",i,tmp_mac,tmp_ip);

		}
		SetColor(2);
		printf("%s",hint);
		int selected_id=-1;
		scanf("%d",&selected_id);
		return selected_id;
		SetColor(0);
	}
};




void HostScan(pcap_t * fp,HostManager & manager,unsigned int srcIP,unsigned int dstIP,MAC srcMAC);
void ARP_cheat(pcap_t * fp,unsigned long targetIP,unsigned long gateIP,MAC myMAC,MAC targetMAC,MAC gateMAC);
#endif