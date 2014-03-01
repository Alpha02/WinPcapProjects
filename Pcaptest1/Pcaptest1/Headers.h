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
#define ARP_OP_REQUEST 0x0100
#define ARP_OP_REPLY   0x0200
class HostManager;
#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define getIP(strIP) (inet_addr((strIP)))
MAC getMAC(char * strMAC);
void MAC_copy(MAC src,MAC dst);
char * package_Receive(pcap_t * fp);
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
void send_raw_package(pcap_t * fp,u_char * packet,int packet_size,int times);
void HostScan(pcap_t * fp,unsigned int srcIP,unsigned int dstIP,MAC srcMAC);
void ARP_cheat(pcap_t * fp,unsigned long targetIP,unsigned long gateIP,MAC myMAC,MAC targetMAC,MAC gateMAC);
#endif