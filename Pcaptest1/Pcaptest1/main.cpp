#define HAVE_REMOTE
#include <stdio.h>
#include <pcap.h>
#include "Headers.h"
char ARP_TABLE[100][2][30]={
	"10.2.124.2"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.3"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.4"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.6"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.7"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.8"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.9"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.10"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.11"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.12"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.13"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.14"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.15"     ,    "ec-17-2f-32-3e-55"
	,"10.2.124.16"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.18"     ,    "08-10-77-cd-98-4b"
	,"10.2.124.19"     ,    "84-8f-69-d0-25-48"
	,"10.2.124.20"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.21"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.22"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.23"     ,    "0c-82-68-8b-03-f1"
	,"10.2.124.25"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.26"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.27"     ,    "c8-3a-35-22-00-a8"
	,"10.2.124.28"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.29"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.30"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.31"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.32"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.34"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.35"     ,    "00-26-fc-a2-9c-b5"
	,"10.2.124.36"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.37"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.38"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.39"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.40"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.41"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.42"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.44"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.46"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.47"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.49"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.50"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.59"     ,    "10-dd-b1-df-17-c9"
	,"10.2.124.81"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.82"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.87"     ,    "54-53-ed-ab-9c-d9"
	,"10.2.124.103"     ,    "24-b6-fd-45-14-17"
	,"10.2.124.104"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.109"     ,    "b8-88-e3-37-d8-41"
	,"10.2.124.117"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.119"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.121"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.127"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.133"     ,    "a8-20-66-08-ce-c5"
	,"10.2.124.149"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.161"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.168"     ,    "3c-97-0e-6b-65-37"
	,"10.2.124.169"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.183"     ,    "a8-20-66-08-ce-c5"
	,"10.2.124.187"     ,    "b8-88-e3-37-13-fb"
	,"10.2.124.192"     ,    "54-04-a6-aa-7b-d0"
	,"10.2.124.194"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.197"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.201"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.203"     ,    "b8-88-e3-a0-66-09"
	,"10.2.124.208"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.214"     ,    "8c-21-0a-d8-db-a6"
	,"10.2.124.215"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.219"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.229"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.233"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.237"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.242"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.248"     ,    "d8-49-0b-b8-4a-1b"
	,"10.2.124.249"     ,    "d8-49-0b-b8-4a-1b"
};
#define ARP_ip(X) (ARP_TABLE[(X)][0])
#define ARP_mac(X) (ARP_TABLE[(X)][1])

void rand_source_ip_mac(u_char * buff){
	MACHeader *pMAC = (MACHeader*)buff;
	unsigned int x=rand()%75;
	Package_Change_srcMAC(buff,getMAC(ARP_mac(x)));
	Package_Change_srcIP(buff,getIP(ARP_ip(x)));
	IPHeader * pIPHeader=(IPHeader *)(buff+sizeof(MACHeader));
	pIPHeader->checksum=0;
	pIPHeader->checksum=CheckSum((USHORT*)(buff+sizeof(MACHeader)),sizeof(IPHeader));
	ICMPHeader *pICMPHeader = (ICMPHeader*)(buff+sizeof(MACHeader)+sizeof(IPHeader));
	pICMPHeader->cksum=0;
	pICMPHeader->cksum=CheckSum((USHORT *)(buff+sizeof(MACHeader) + sizeof(IPHeader)),sizeof(ICMPHeader));

}
pcap_if_t * find_interfaces(){
	pcap_if_t * alldevs;
	pcap_if_t * d;
	int i=0;
	printf("finding interfaces...");
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_findalldevs(&alldevs,errbuf)==-1){
		printf("Error:%s\n",errbuf);
		exit(1);
	}
	for(d=alldevs;d;d=d->next){
		printf("\nDevice [ %d ] : ",i);
		if(d->description)	printf("(%s)\n",d->description);
		else printf("(No description available)\n");
		i++;
	}
	if(i==0){
		printf("No interfaces found!");
	}
	return alldevs;
}
pcap_t * openDevice(pcap_if_t * device,unsigned int package_size){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * fp=pcap_open(device->name,65535,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf);
	if(fp == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
		
	}
	return fp;
}
void send_raw_package(pcap_t * fp,u_char * packet,int packet_size,int times=1){

		char errbuf[PCAP_ERRBUF_SIZE];
		/* Send down the packet */
		while(times--){
			//rand_source_ip_mac(packet);
			if (pcap_sendpacket(fp, packet, packet_size ) != 0)
			{
				fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
				return;
			}
		}
		return;
}

int main(){
	srand((unsigned)time(NULL)); 
	pcap_if_t * alldevs=find_interfaces();
	//char * buff=ICMP_MakePackage(getIP(ARP_ip(0)),getIP("222.30.32.11"),getMAC(ARP_mac(0)),getMAC("D8:49:0B:B8:4a:1b"),0);
	unsigned long temp_ip=getIP("10.2.124.1");
	unsigned int package_size=sizeof(MACHeader)+sizeof(IPHeader)+sizeof(ICMPHeader);
	char * pData=new char[package_size];
	pcap_t * fp=openDevice(alldevs,package_size);
	HostScan(fp,getIP("10.2.124.96"),temp_ip,getMAC("78-45-C4-B8-12-CE"));
	//SetFilter(fp,"arp and ether dst 78:45:C4:B8:12:CE");
	
	/*
	for(int i=0;i<255;i++){
		ARP_MakePackage(pData,ARP_OP_REQUEST,getMAC("78-45-C4-B8-12-CE"),getMAC("ff-ff-ff-ff-ff-ff"),getIP("10.2.124.60"),temp_ip+(i<<24));
		send_raw_package(fp,(u_char *)buff,package_size,1);
		
	}
	*/
	while(1){package_Receive(fp);}
	return 0;
}