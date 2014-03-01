#include "Headers.h"
class Host{
public:
	MAC mac;
	unsigned int IP;
	unsigned int port_number;
	unsigned int * port_list;
};
class HostManager{
public:
	unsigned int host_number;
	Host * host_list;
	HostManager(){
		host_number=0;
		host_list=new Host[500];
	}
	void newHost(Host nh){
		host_list[host_number]=nh;
	}
	bool newHost(MAC mac,unsigned int IP){
		if(host_number>=500)return 0;
		host_list[host_number].IP=IP;
		host_list[host_number].mac=mac;
		host_number++;
		return 1;
	}
	Host getHost(unsigned int idx){
		return host_list[idx];
	}
	int getHostByIP(unsigned long targetIP){
		for(int i=0;i<host_number;i++){
			if(host_list[i].IP==targetIP){
				return i;
			}
		}
		return -1;
	}
	int getHostByMAC(MAC targetMAC){
		for(int i=0;i<host_number;i++){
			if(MAC_equal((host_list[i].mac),targetMAC)){
				return i;
			}
		}
		return -1;
	}
	void ARP_read(char * pData){
		unsigned int package_size=sizeof(MACHeader)+sizeof(ARPHeader);
		MACHeader * pMACHeader=(MACHeader *)(pData);
		ARPHeader * pARPHeader=(ARPHeader *)(pData+sizeof(MACHeader));
		if(getHostByIP(pARPHeader->IP_sender)<0){
			newHost(pARPHeader->MAC_sender,pARPHeader->IP_sender);
			printf("DiscoverHost--> %d\n",pARPHeader->IP_sender);
		}
	}
	int getGateWay(){
		for(int i=0;i<host_number;i++){
			if(host_list[i].IP>>24==1)return i;
		}
		return -1;
	}
	void lookClearDHCP(){
		int host_gt=getGateWay();
		int new_array_i=0;
		for(int i=0;i<host_number;i++){
			if((host_gt==i) || (!MAC_equal(host_list[host_gt].mac,host_list[i].mac))){
				host_list[new_array_i++]=host_list[i];
			}
		}
		host_number=new_array_i;
	}
};
void SetFilter(pcap_t * fp,char * str){
	bpf_program fcode;
	unsigned long netmask=0xffffff; 

	if (pcap_compile(fp, &fcode, str, 1, netmask) < 0)
	{
		printf("\nUnable to compile the packet filter. Check the syntax.\n");
		return;
	}
		if (pcap_setfilter(fp, &fcode) < 0)
		{
			printf("\nError setting the filter.\n");

			return;
		}
}

void HostScan(pcap_t * fp,unsigned int srcIP,unsigned int dstIP,MAC srcMAC){
	char src_mac_str[20];
	MAC_toString(srcMAC,src_mac_str);
	char * filter=new char[100];
	strcpy(filter,"arp and ether dst ");
	filter=strcat(filter,src_mac_str);
	SetFilter(fp,filter);
	unsigned int package_size=sizeof(MACHeader)+sizeof(IPHeader)+sizeof(ICMPHeader);
	char * pData=new char[package_size];
	char try_times[255];
	for(int i=0;i<255;i++){
		try_times[i]=0;
	}
	HostManager manager;
	while(1){
		char *recvData;
		bool scan_over=true;
		int j=0;
		for(int i=0;i<255;i++){

			unsigned int tmp_ip=dstIP+(i<<24);
			if((try_times[i]>2)||(manager.getHostByIP(tmp_ip)>=0)|| j>20){
				continue;
			}else{
				scan_over=false;
			}
			j++;
			try_times[i]++;
			printf("Scanning--> %d\n",i);
			ARP_MakePackage(pData,ARP_OP_REQUEST,getMAC(src_mac_str),getMAC("ff-ff-ff-ff-ff-ff"),srcIP,dstIP+(i<<24));
			send_raw_package(fp,(u_char *)pData,package_size,1);
		}
		recvData=package_Receive(fp);
		while(recvData){
			manager.ARP_read(recvData);
			recvData=package_Receive(fp);
		}
		if(scan_over){
			break;
		}
	}
	int a=manager.getGateWay();
	manager.lookClearDHCP();
	while(1){}
}