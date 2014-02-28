#include <stdio.h>
#include "pcap.h"
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
int main(){
	pcap_if_t * alldevs=find_interfaces();
	system("PAUSE");
}