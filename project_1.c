/*
 * Credit goes to the Tcpdump Group for the structure and macro definitions,
 * tcp/ip header definitions, and pcap device and session setup
 * used in this program.
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; 				/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;				/* version << 4 | header length >> 2 */
	u_char ip_tos;				/* type of service */
	u_short ip_len;				/* total length */
	u_short ip_id;				/* identification */
	u_short ip_off;				/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;				/* time to live */
	u_char ip_p;				/* protocol */
	u_short ip_sum;				/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

/*
 * Prints packet payload data
 */
void print_payload(const u_char *payload, int len)
{
	int i;
	const u_char *ch = payload;

	for (i = 0; i < len; i++) {
		if (strncmp((char*) ch, "\r\n\r\n", 4) == 0) {
			break;
		} else if (strncmp((char*) ch, "\r\n", 2) == 0) {
			printf("\r\n");
			ch++;
			i++;
		} else if (isprint(*ch)) {
			printf("%c", *ch);
		}
		ch++;
	}

	printf("\r\n\r\n");
	printf("\n");

	return;
}

/*
 * Dissects packet into ip header, tcp header, and payload components
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	
	/* Declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	/* Define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* Define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	/* Define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	/* Define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* Compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string. Checks http method to determine
	 * if it's a request or response.
	 */
	if (size_payload > 0) {
		int type;

		if (strncmp((char*) payload, "GET", 3) == 0 ||
			strncmp((char*) payload, "HEAD", 4) == 0 ||
			strncmp((char*) payload, "POST", 4) == 0 ||
			strncmp((char*) payload, "PUT", 3) == 0 ||
			strncmp((char*) payload, "DELETE", 6) == 0 ||
			strncmp((char*) payload, "CONNECT", 7) == 0 ||
			strncmp((char*) payload, "OPTIONS", 7) == 0 ||
			strncmp((char*) payload, "TRACE", 5) == 0) {
			type = 0;
		} else if (strncmp((char*) payload, "HTTP", 4) == 0) {
			type = 1;
		} else {
			return;
		}

		printf("%d ", count);
		printf("%s:", inet_ntoa(ip->ip_src));
		printf("%d ", ntohs(tcp->th_sport));
		printf("%s:", inet_ntoa(ip->ip_dst));
		printf("%d HTTP ", ntohs(tcp->th_dport));

		if (type == 0) {
			printf("Request\r\n");
		} else {
			printf("Response\r\n");
		}

		print_payload(payload, size_payload);
		count++;
	}

	return;
}


int main(int argc, char **argv) {
	pcap_t *handle;					/* Session handle */
	char *dev = NULL;				/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter expression */
	char filter_exp[] = "tcp port 80";	/* The filter expression */
	bpf_u_int32 mask;				/* The netmask of our sniffing device */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char *packet;			/* The actual packet */

	/* Set the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	    return(2);
	}

	/* Get the device network number and mask */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	printf("\nCapture begin.\n");
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
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

	/* Set callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* Cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
	return(0);
}
