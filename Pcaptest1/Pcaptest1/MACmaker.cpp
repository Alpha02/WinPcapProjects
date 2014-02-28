#include "Headers.h"
void Package_Change_srcMAC(unsigned char * pBuf,unsigned char* newMAC){
	unsigned char *c=((MACHeader*)pBuf)->src_MAC;
	for(unsigned char i=0;i<6;i++){
		c[i]=newMAC[i];
	}
}

void MAC_MakePackage(char * pBuf,unsigned char * srcMAC,unsigned char * dstMAC,u_short protocol_type){
	for(int i=0;i<6;i++){
		pBuf[i]=dstMAC[i];
	}
	for(int i=6;i<12;i++){
		pBuf[i]=srcMAC[i-6];
	}
	u_short * pBufint;
	pBufint=(u_short*)&pBuf[12];
	pBufint[0]=protocol_type;
}
unsigned char MAC_getChar(char c){
	if(c>='a')return c-'a'+10;
	if(c>='A')return c-'A'+10;
	return c-'0';
}
unsigned char * getMAC(char * strMAC){
	unsigned char * newMAC=new unsigned char[6];
	for(unsigned char i=0;i<6;i++){
		newMAC[i]=MAC_getChar(strMAC[i*3+1])+((MAC_getChar(strMAC[i*3]))<<4);
	}
	return newMAC;
}

