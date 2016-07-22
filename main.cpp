#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


void printpacket(u_char *a, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{

	struct ether_header *ethernetheader;
	struct ip *ipheader;
	struct tcphdr *tcpheader;

	// IP Protocol Check
	ethernetheader = (struct ether_header*) packet;
	if(ntohs(ethernetheader->ether_type)!=ETHERTYPE_IP)
	{
		printf("Not IP Protocol");
		return;
	}
	
	// TCP Protocol Check
	ipheader = (struct ip*)(packet+14);
	if(ipheader -> ip_p != IPPROTO_TCP)
	{
		printf("Not TCP Protocol");
		return;
	}
	
	tcpheader = (struct tcphdr*)(packet+14+4*(ipheader->ip_hl));
	printf("\n");
	printf("Source      MAC : %s\n", ether_ntoa((struct ether_addr*)ethernetheader->ether_shost));
	printf("Destination MAC : %s\n", ether_ntoa((struct ether_addr*)ethernetheader->ether_dhost));	
	printf("Souce       IP : %s\n", inet_ntoa(ipheader->ip_src));
	printf("Destination IP : %s\n", inet_ntoa(ipheader->ip_dst));
	printf("Source      port : %d\n", ntohs(tcpheader->th_sport));
	printf("Destination port : %d\n", ntohs(tcpheader->th_dport));
	
}



int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dname;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int i;
	
	/* Find All Devices */
	
	pcap_if_t **alldevices;
	pcap_if_t *device;
	if(pcap_findalldevs(alldevices, errbuf)==-1)
	{
		printf("No Devices");
		return -1;
	}
	device=alldevices[0];	
	for(int i=0; device!=NULL; device=device->next, i++)
	{
		printf("%dth device name : %s\n",i+1, device->name);
	} 
	
	/* select a device*/
	int devicenum;
	printf("Input Device Number : ");
	scanf("%d", &devicenum);
	device=alldevices[0];
	for(int i=0; i<devicenum-1; i++)
	{
		device=device->next;
	}
	
	dname=device->name;
	/* Find the properties for the device */
	if (pcap_lookupnet(dname, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dname, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dname, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dname, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	pcap_loop(handle, 0, printpacket, NULL);
	return(0);
}
