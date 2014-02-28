#include "Headers.h"
void Package_Change_srcIP(unsigned char * pBuf,unsigned long newIP){
	((IPHeader*)(pBuf+sizeof(MACHeader)))->sourceIP=newIP;
}
void IP_MakePackage(char * pBuf,unsigned int package_size,unsigned long srcIP,unsigned long dstIP,u_short id){
	memset(pBuf,0,sizeof(IPHeader));
	IPHeader * pIPHeader=(IPHeader *)pBuf;
	int nVersion=4;
	int nHeadSize=sizeof(IPHeader)/4;
	unsigned long destIP=dstIP;
	pIPHeader->ver_hlen=(nVersion<<4)|nHeadSize;
	pIPHeader->tos=0;
	pIPHeader->total_len=htons(package_size);
	pIPHeader->ident=htons(1234);
	pIPHeader->frag_and_flags=0;
	pIPHeader->ttl=255;
	pIPHeader->proto=IPPROTO_ICMP;
	pIPHeader->checksum=0;
	pIPHeader->sourceIP=srcIP;
	pIPHeader->destIP=destIP;
	pIPHeader->checksum=CheckSum((USHORT*)pBuf,sizeof(IPHeader));
}
