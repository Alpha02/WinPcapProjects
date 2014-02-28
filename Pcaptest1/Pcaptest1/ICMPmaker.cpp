#include "Headers.h"
char * ICMP_MakePackage(unsigned long srcIP,unsigned long dstIP,unsigned char * srcMAC,unsigned char * dstMAC,u_short id){
	unsigned int package_size=sizeof(MACHeader)+sizeof(IPHeader)+sizeof(ICMPHeader);
	char * pData=new char[package_size];
	MAC_MakePackage(pData,srcMAC,dstMAC,8);
	IP_MakePackage(pData+sizeof(MACHeader),package_size,srcIP,dstIP,id);
	ICMPHeader *pICMPHeader = (ICMPHeader*)(pData+sizeof(MACHeader)+sizeof(IPHeader));
	pICMPHeader->type=ICMP_ECHO_REQUEST;
	pICMPHeader->code=0;
	pICMPHeader->cksum=0;
	pICMPHeader->id=htons(rand());
	pICMPHeader->seq=htons(rand());
	pICMPHeader->cksum=CheckSum((USHORT *)((char *)pData +sizeof(MACHeader)+ sizeof(IPHeader)),sizeof(ICMPHeader));
	return pData;
}
