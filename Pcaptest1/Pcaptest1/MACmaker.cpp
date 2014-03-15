#include "Headers.h"
void MAC_copy(MAC src,MAC dst){
	for(unsigned char i=0;i<6;i++){
		dst.addr[i]=src.addr[i];
	}
}
void Package_Change_srcMAC(unsigned char * pBuf,MAC newMAC){
	MAC c=((MACHeader*)pBuf)->src_MAC;
	MAC_copy(newMAC,c);
}

void MAC_MakePackage(Package & pack,MAC srcMAC,MAC dstMAC,u_short protocol_type){
	u_char * pBuf=pack.addSection(sizeof(MACHeader));
	for(int i=0;i<6;i++){
		pBuf[i]=dstMAC.addr[i];
	}
	for(int i=6;i<12;i++){
		pBuf[i]=srcMAC.addr[i-6];
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
bool MAC_equal(MAC src1,MAC src2){
	for(int i=0;i<6;i++){
		if(src1.addr[i]!=src2.addr[i])return false;
	}
	return true;
}
void MAC_toString(MAC mac,char * str){
	for(int i=0;i<5;i++){
		sprintf(str+i*3,"%02x:",(unsigned char)mac.addr[i]);
	}
	sprintf(str+15,"%02x",(unsigned char)mac.addr[5]);
	str[18]=0;
}
	
MAC getMAC(char * strMAC){
	MAC newMAC;
	for(unsigned char i=0;i<6;i++){
		newMAC.addr[i]=MAC_getChar(strMAC[i*3+1])+((MAC_getChar(strMAC[i*3]))<<4);
	}
	return newMAC;
}

