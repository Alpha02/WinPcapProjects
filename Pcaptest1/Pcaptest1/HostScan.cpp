#include "Headers.h"

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

void HostScan(pcap_t * fp,HostManager & manager,unsigned int srcIP,unsigned int dstIP,MAC srcMAC){
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
	while(1){
		char *recvData;
		bool scan_over=true;
		int j=0;
		printf("\nScanning...");
		for(int i=0;i<255;i++){

			unsigned int tmp_ip=dstIP+(i<<24);
			if((try_times[i]>2)||(manager.getHostByIP(tmp_ip)>=0)|| j>200){
				continue;
			}else{
				scan_over=false;
			}
			j++;
			try_times[i]++;
			SetColor(3);

			ARP_MakePackage(pData,ARP_OP_REQUEST,getMAC(src_mac_str),getMAC("ff-ff-ff-ff-ff-ff"),srcIP,dstIP+(i<<24));
			send_raw_package(fp,(u_char *)pData,package_size,1);
		}
		pcap_pkthdr tmp_header;
		recvData=package_Receive(fp,tmp_header);
		while(recvData){
			manager.ARP_read(recvData);
			recvData=package_Receive(fp,tmp_header);
		}
		if(scan_over){
			break;
		}
	}
	int a=manager.getGateWay();
	manager.lookClearDHCP();
}