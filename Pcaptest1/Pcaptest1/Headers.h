#ifndef HEADERS_H
#define HEADERS_H
#pragma comment(lib,"ws2_32.lib")
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <pcap.h>
struct MACHeader{
	unsigned char dest_MAC[6];
	unsigned char src_MAC[6];
	unsigned short protocol_type;
};
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
#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define getIP(strIP) inet_addr((strIP))
unsigned char * getMAC(char * strMAC);
void Package_Change_srcMAC(unsigned char * pBuf,unsigned char* newMAC);
void Package_Change_srcIP(unsigned char * pBuf,unsigned long newIP);
void MAC_MakePackage(char * pBuf,unsigned char *srcMAC,unsigned char *dstMAC,u_short protocol_type);
void IP_MakePackage(char * pBuf,unsigned int package_size,unsigned long srcIP,unsigned long dstIP,u_short id);
char * ICMP_MakePackage(unsigned long srcIP,unsigned long dstIP,unsigned char * srcMAC,unsigned char * dstMAC,u_short id);
USHORT CheckSum(USHORT * pUShort,int size);
#endif