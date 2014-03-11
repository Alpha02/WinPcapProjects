#include "Headers.h"
void TCP_MakePackage(Package * pack,USHORT srcPort,USHORT destPort,u_int seq_num){
	//目前用于产生SYN Flood
	char * section_data=pack->addSection(sizeof(TCPHeader));
	TCPHeader * pTCPHeader=(TCPHeader *)(section_data);
	pTCPHeader->sourcePort=htons(srcPort);
	pTCPHeader->destPort=htons(destPort);
	pTCPHeader->seq_number=htonl(seq_num);
	//pTCPHeader->ack_number=htonl(0xac487bc9);	
	//pTCPHeader->seq_number=htonl(0x28376839+seq_num);

	//填充TCP伪首部（用于计算校验和，并不真正发送）
	IPHeader * iph=(IPHeader *)pack->getSection(1);
	unsigned char checkbuff[sizeof(TCPpsdHeader)+sizeof(TCPHeader)+12];	
	TCPpsdHeader *psdheader=(TCPpsdHeader *) &checkbuff;	
	psdheader->srcAddr=iph->sourceIP;								//源地址
	psdheader->dstAddr=iph->destIP;									//目的地址
	psdheader->mbz=0;
	psdheader->ptcl=IPPROTO_TCP;									//协议类型
	psdheader->tcplen=htons(sizeof(TCPHeader)+12);							//TCP首部长度
	pTCPHeader->ack_number=0;	
	pTCPHeader->lenres=(sizeof(TCPHeader)+12)/4<<4|0;     //TCP长度和保留位
	pTCPHeader->flag=0x02;
	pTCPHeader->window=htons(0x2000);
	pTCPHeader->urgent_pointer=0;
	pTCPHeader->checksum=0;
	char * opt=pack->addSection(12);
	opt[0]=0x02;
	opt[1]=0x04;
	opt[2]=0x05;
	opt[3]=0xb4;
	opt[4]=0x01;
	opt[5]=0x03;
	opt[6]=0x03;
	opt[7]=0x02;
	opt[8]=0x01;
	opt[9]=0x01;
	opt[10]=0x04;
	opt[11]=0x02;
	memcpy((checkbuff)+sizeof(TCPpsdHeader),section_data,sizeof(TCPHeader)+12);
	pTCPHeader->checksum=CheckSum((USHORT*)&checkbuff,sizeof(TCPpsdHeader)+sizeof(TCPHeader)+12);
	//pTCPHeader->checksum=0;
	//pTCPHeader->checksum=CheckSum((USHORT*)pTCPHeader,sizeof(TCPHeader));
}
