#include "Headers.h"
USHORT CheckSum(USHORT * pUShort,int size){
	unsigned long cksum=0;
	while(size>1){
		cksum+=*pUShort++;
		size-=sizeof(USHORT);
	}
	if(size){
		cksum+=*(UCHAR *)pUShort;

	}
	cksum=(cksum>>16)+(cksum&0xffff);
	cksum+=(cksum>>16);
	return (USHORT)(~cksum);
}