#include "Headers.h"
char * ICMP_MakePackage(unsigned long srcIP,unsigned long dstIP,MAC srcMAC,MAC dstMAC,u_short id){
	unsigned int package_size=sizeof(MACHeader)+sizeof(IPHeader)+sizeof(ICMPHeader);
	char * pData=new char[package_size];
	MAC_MakePackage(pData,srcMAC,dstMAC,MAC_PROTOCOL_TYPE_IP);
	IP_MakePackage(pData+sizeof(MACHeader),package_size,srcIP,dstIP,id,IPPROTO_ICMP,20);
	ICMPHeader *pICMPHeader = (ICMPHeader*)(pData+sizeof(MACHeader)+sizeof(IPHeader));
	pICMPHeader->type=ICMP_ECHO_REQUEST;
	pICMPHeader->code=0;
	pICMPHeader->cksum=0;
	pICMPHeader->id=htons(rand());
	pICMPHeader->seq=htons(rand());
	pICMPHeader->cksum=CheckSum((USHORT *)((char *)pData +sizeof(MACHeader)+ sizeof(IPHeader)),sizeof(ICMPHeader));
	return pData;
}
