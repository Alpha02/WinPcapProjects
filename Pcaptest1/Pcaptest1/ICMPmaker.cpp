#include "Headers.h"
void ICMP_MakePackage(Package & pack,unsigned long srcIP,unsigned long dstIP,MAC srcMAC,MAC dstMAC,u_short id){
	pack.create(sizeof(MACHeader)+sizeof(IPHeader)+sizeof(ICMPHeader));
	//char * pData=new char[pack.length];
	MAC_MakePackage(pack,srcMAC,dstMAC,MAC_PROTOCOL_TYPE_IP);
	IP_MakePackage(pack,srcIP,dstIP,id,IPPROTO_ICMP,20);
	u_char * pData=pack.addSection(sizeof(ICMPHeader));
	ICMPHeader *pICMPHeader = (ICMPHeader*)pData;
	pICMPHeader->type=ICMP_ECHO_REQUEST;
	pICMPHeader->code=0;
	pICMPHeader->cksum=0;
	pICMPHeader->id=htons(rand());
	pICMPHeader->seq=htons(rand());
	pICMPHeader->cksum=CheckSum((USHORT *)pData,sizeof(ICMPHeader));
}
