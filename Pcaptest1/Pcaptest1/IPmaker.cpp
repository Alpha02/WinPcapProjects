#include "Headers.h"
void Package_Change_srcIP(unsigned char * pBuf,unsigned long newIP){
	((IPHeader*)(pBuf+sizeof(MACHeader)))->sourceIP=newIP;
}
void IP_MakePackage(Package & pack,unsigned long srcIP,unsigned long dstIP,u_short id,char protocol_type,USHORT total_len){
	u_char * pBuf=pack.addSection(sizeof(IPHeader));
	IPHeader * pIPHeader=(IPHeader *)pBuf;
	int nVersion=4;
	int nHeadSize=sizeof(IPHeader)/4;
	unsigned long destIP=dstIP;
	pIPHeader->ver_hlen=(nVersion<<4)|nHeadSize;
	pIPHeader->tos=0;
	pIPHeader->total_len=htons(total_len);
	pIPHeader->ident=htons(id);
	pIPHeader->frag_and_flags=0x0040;
	pIPHeader->ttl=64;
	pIPHeader->proto=protocol_type;
	pIPHeader->checksum=0;
	pIPHeader->sourceIP=srcIP;
	pIPHeader->destIP=destIP;
	pIPHeader->checksum=CheckSum((USHORT*)pBuf,sizeof(IPHeader));
}
void IP_toString(unsigned long IP,char * str){
	sprintf(str,"%d.%d.%d.%d",(IP)&0x000000ff,(IP>>8)&0x000000ff,(IP>>16)&0x000000ff,IP>>24);
}