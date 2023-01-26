// cc main.c -pthread -lpcap -static
//cc main.c -std=gnu -lpcap
// cc main.c -pthread -lpcap -static -o linuxnet
// sudo ./linuxnet -i 192.168.1.207 -d 0 -n 0 -f testtt -h 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>  
#include <math.h>
#include <time.h>
#include <pthread.h>				// add option -pthread 
#include <unistd.h>					// for Sleep 
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>


#include <netdb.h>

#include <dirent.h>
#include <stdbool.h>
#define SEND 0
#define RECEIVE 1
#define MAXKEY 128
short xport[5] = {88,135,389,3268,445};
time_t starttime;
time_t curtime;
unsigned long durationinsec = 30;
pcap_t* handle;
FILE* fOut;
char hostname[HOST_NAME_MAX + 1];
char msg[256];
char msglong[1024];
char dmsglong[2048];
char outputpath[256];
char proccmdline[1024];
char mytargetip[20];
char retline[1024];
char retna[2];
// Run Options 
int excludeport  = 0;
int loglevel = 0;
int resolvelevel = 0;
bool storeinfile = false;
bool panic = false;	
char nullblank [MAXKEY] = {'\0'};

#define port u_int16_t
#define OK(x) ((x) > -1)
#define LISTENING (0x0A)
#define INT_TO_ADDR(_addr) \
(_addr & 0xFF), \
(_addr >> 8 & 0xFF), \
(_addr >> 16 & 0xFF), \
(_addr >> 24 & 0xFF)
#define ADDR_LEN (INET6_ADDRSTRLEN + 1 + 5 + 1)
#define MAX_PROCESS 4096
#define MAX_TCPCONV 1024
#define O_RDONLY         00
#define O_WRONLY         01
#define O_RDWR           02

int serverport[64096] = { 0 };

struct rec
{
	char  key[64];//position
	long nbpaket;
};

 
struct conv
{
	char  key[128];//position
	long nbpaketin;
	long nbpaketout;
	char  retline[1024];//position
};

struct conv convlist[MAX_TCPCONV];

void logit(int level, char* msg)
{
	time_t timer;
	char buffer[26];
	char msgout[1240];
	msgout[0]='\0';
	struct tm* tm_info;
	 
	if (level > loglevel)
		return;
	timer = time(NULL);
	tm_info = localtime(&timer);
	strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
	//sprintf(msgout, "%s %s", buffer,msg);
	strcat(msgout,buffer);
	strcat(msgout,";");
	strcat(msgout,msg);
	printf("%s\n",msgout);
	 fflush(stdout);


}

bool isexcluded(short a)
{
	bool ret = false;
	for ( int i = 0; i < sizeof(xport)/sizeof(xport[0]); i++) {
		if (xport[i]== a)
			{	
				ret=true;
				break;
			}
	}

return ret;
} 
 
void addserverport(int port)
{
 
if (serverport[port] == 0 )
	serverport[port] = port;
 
}

bool isserverport(int port)
{
	if (serverport[port]!= port)
	return false;
	return true;

	bool server = false;
	int k = 0;
	for (k = 0; k < sizeof(serverport); k++)
	{
		if (serverport[k] == port)
		{
		//	printf("port already registred \n");
			server = true;
			break;
		}
		 
	}
	 return server;
}
 
void initkeylist()
{
	 
	int k = 0;
 
	for ( k = 0; k < MAX_TCPCONV; k++)
	{
		 
		strncpy(convlist[k].key,nullblank,MAXKEY);    
	    convlist[k].nbpaketin = 0; 
		convlist[k].nbpaketin = 0; 
		 
	}
 
}
 
char* getcmdline(int processid)
{
	
	char procfile[1024];
	char name[4096];
	sprintf(procfile, "/proc/%d/cmdline", processid);
	int fd = open(procfile, O_RDONLY);
	int size = read(fd, name, sizeof(procfile));
	close(fd);
	name[1000] = '\0';
	proccmdline[0]='\0';
	strcat(proccmdline,name);
	return (char*) proccmdline;
	
}
unsigned long readtcp_net_byport(int port)
{

	bool inodefound = false;
	FILE* tcp = fopen("/proc/net/tcp", "r");
	char* line = NULL;
	size_t n = 0;
	int i = 0;
	typedef union _iaddr {
		unsigned u;
		unsigned char b[4];
	} iaddr;


	unsigned int conn_state;
	unsigned lport, rport, state, txq, rxq, num, uid;
	unsigned long inode = 0;
	iaddr laddr, raddr;
	i = 0;
	while OK(getline(&line, &n, tcp))
		 
	{
		if (i = !0)
		{
			int nitems = sscanf(line, " %d: %x:%x %x:%x %x %x:%x %*X:%*X %*X %d %*d %ld",
				&num, &laddr.u, &lport, &raddr.u, &rport, &state, &txq,
				&rxq, &uid, &inode);
			if (nitems == 10)
			{
				 
				if  ((inode != 0)   && (lport == port))
				{
					inodefound=true;
					break;
				}
				if  ((inode == 0)   && (lport == port))
				{
					inodefound=true;
					break;
				}
			}
		}
	}
	i++;
	if (!inodefound)
		inode=0;
	//	printf("out-readtcp_net_byport %s\n",hostname);
	return inode;
}
 
 
char*  getprocessbyinode(unsigned long inode)
{
 
	char process[1024];
	
	const char* root = getenv("PROC_ROOT") ? : "/proc/";
	struct dirent* d;
	char name[1024];
	int nameoff;
	DIR* dir;
	char* ret;
	
 

	strcpy(name, root);
	if (strlen(name) == 0 || name[strlen(name) - 1] != '/')
		strcat(name, "/");
	nameoff = strlen(name);
	dir = opendir(name);
  
	if (!dir)
		return (char*)"NA";
 
	ret = process;
	while ((d = readdir(dir)) != NULL) {
		struct dirent* d1;
		int pid, pos;
		DIR* dir1;
		char crap;
		if (sscanf(d->d_name, "%d%c", &pid, &crap) != 1)
			continue;
		sprintf(name + nameoff, "%d/fd/", pid);
		 
	 	
		pos = strlen(name);
	 
		if ((dir1 = opendir(name)) == NULL)
			continue;
		process[0] = '\0';
	 
		while ((d1 = readdir(dir1)) != NULL) {
			const char* pattern = "socket:[";
			unsigned int ino;
			char lnk[64];
			int fd;
			ssize_t link_len;

			if (sscanf(d1->d_name, "%d%c", &fd, &crap) != 1)
				continue;
		 
			sprintf(name + pos, "%d", fd);

			link_len = readlink(name, lnk, sizeof(lnk) - 1);
	 
			if (link_len == -1)
				continue;
			lnk[link_len] = '\0';

			if (strncmp(lnk, pattern, strlen(pattern)))
				continue;
		 
			sscanf(lnk, "socket:[%u]", &ino);
		 
			if (process[0] == '\0') {
				char tmp[1024];
				FILE* fp;

				snprintf(tmp, sizeof(tmp), "%s/%d/stat", root, pid);
		 
				if ((fp = fopen(tmp, "r")) != NULL) {
					fscanf(fp, "%*d (%[^)])", process);
					fclose(fp);
				}
			}
			
			if (ino == (int) inode)
			{
	 		 
				getcmdline(pid);
			 	process[16] = '\0'; 
				sprintf(retline,"%s;%s",ret,proccmdline);
		 	  	closedir(dir1);
				closedir(dir);
				return  (char*) retline;
			}
		}
	 
		closedir(dir1);
	}
 
	closedir(dir);
 
    
	return (char*)retna;
}
 
void updateconvlist(int dir , char* key, char* remoteaddr, u_short p,u_short tcplen)
{
 
int res=0;
bool entry = false;

socklen_t len;         /* input */
char hbuf[NI_MAXHOST];
 
 
int k = 0;
struct sockaddr_in sa;
char myhostname[NI_MAXHOST];
char outline[2050];
char host[NI_MAXHOST];

outline[0]='\0';
msglong[0]='\0';
sprintf(msg, "Test :%s with %s and port :%d\n", key, remoteaddr,p);
logit(3, msg);
sprintf(msg, "key:%s\n", key);
logit(3, msg);
	for (k = 0; k < MAX_TCPCONV; k++)
	{ 
		if (strlen(convlist[k].key) == 0) {
			strncpy(convlist[k].key,key,128);
		 
			break;
		}
		if (strncmp(convlist[k].key, key,128) == 0) 	{ 
			entry = true;	
			if ((dir == SEND) && (tcplen > 0 ))
					 convlist[k].nbpaketout++;
			if ((dir == RECEIVE) && (tcplen > 0 ))
					 convlist[k].nbpaketin++;
		 
			break;
		}
	}
	if ( k == (MAX_TCPCONV-1)) 	{	
		panic = true;
		//return;
		}
	
	if (!entry)
	{
		if (resolvelevel == 1)
		{
			printf("resolve \n");
			sa.sin_family = AF_INET;
			int c = 	inet_pton(AF_INET, remoteaddr, &sa.sin_addr);
			printf("resolve1 with %s rc %d \n",remoteaddr,c); 
		 	struct hostent *hp;  
			hp = gethostbyaddr((const void *)&sa.sin_addr,sizeof(sa.sin_addr), sa.sin_family);
  
		}

		else
		{
			sprintf(msglong, "%s", key);
		}
	
			convlist[k].retline[0]='\0';
			unsigned long mysoc = readtcp_net_byport(p);

						if (mysoc == 0) {	
							strcat(outline,msglong);
							strcat(outline,";NA");
							strcat(convlist[k].retline,"NA");
							}
						else {	
							getprocessbyinode(mysoc);
							strcat(outline,msglong);
							strcat(outline,";");
							strcat(outline,retline);
							strcat(convlist[k].retline,retline);
						}
		
		logit(0, outline);
	
		if (storeinfile) {
				fOut = fopen(outputpath, "a");
				strcat(outline,"\n");
				fputs(outline, fOut);
				fclose(fOut);
				 
				 
				}
	}

	else {
 	}
 
}

void my_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	u_short ippayload_len;  
	u_short tcppayload_len;  
	typedef u_int tcp_seq;
	typedef struct sniff_tcp2 {
		u_short th_sport;               /* source port */
		u_short th_dport;               /* destination port */
		tcp_seq th_seq;                 /* sequence number */
		tcp_seq th_ack;                 /* acknowledgement number */
		u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
		u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_SYNACK  0x12
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;                 /* window */
		u_short th_sum;                 /* checksum */
		u_short th_urp;                 /* urgent pointer */
	} sniff_tcp2;




	typedef struct ip_address {
		u_char byte1;
		u_char byte2;
		u_char byte3;
		u_char byte4;
	}ip_address;
	/* IPv4 header */
	
	typedef struct ip_header {
		u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
		u_char  tos;            // Type of service 
		u_short tlen;           // Total length 
		u_short identification; // Identification
		u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
		u_char  ttl;            // Time to live
		u_char  proto;          // Protocol
		u_short crc;            // Header checksum
		ip_address  saddr;      // Source address
		ip_address  daddr;      // Destination address
		u_int   op_pad;         // Option + Padding
	}ip_header;
	typedef struct udp_header {
		u_short sport;          // Source port
		u_short dport;          // Destination port
		u_short len;            // Datagram length
		u_short crc;            // Checksum
	}udp_header;
	
	struct tm ltime;
	char process[16];
 	char timestr[16];
	char remoteaddr[16];
	
	char dip[16];
	char sip[16];
	char dir[74];
	char reckey[128] = { };
	char sendkey[128] = { };
	unsigned long inode;
	ip_header* ih;
	udp_header* uh;
	sniff_tcp2* uh2;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	
		if (panic) 	{ 
				pcap_breakloop(handle);
			
				return;
		}


 
		ih = (ip_header*)(pkt_data + 14); //length of ethernet header
		switch (ih->proto) {
		case IPPROTO_TCP:
			time(&curtime);
			unsigned long secondes = (unsigned long) difftime( curtime, starttime );
			if (secondes > durationinsec )
				pcap_breakloop(handle);			
			ip_len = (ih->ver_ihl & 0xf) * 4;
 
			uh = (udp_header*)((u_char*)ih + ip_len);
			uh2 = (sniff_tcp2*)((u_char*)ih + ip_len);
			sport = ntohs(uh2->th_sport);
			dport = ntohs(uh2->th_dport);
			ippayload_len = ntohs(ih->tlen);
			sprintf(sip, "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
			sprintf(dip, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			int i = 0;
			// 
				if (isexcluded(sport) || isexcluded(dport))
				return;
			// Exclude SSH 
		//	if ((sport == 22 ) || (dport ==22 ))
		//	return;
			 
			if ( (strstr(mytargetip, dip) == NULL) && (strstr(mytargetip, sip) == NULL )) {
				return; 
			}
			tcppayload_len = ippayload_len - 40;
	 
			if (excludeport != 0 ) {
				if  ((sport == excludeport) || (dport ==  excludeport))
					return;
			}

			if (strstr(mytargetip, dip))
			{
				
				if (uh2->th_flags == TH_SYN)
				{
 					 
					addserverport(dport);
					sprintf(dir, "%s;%s;", "SERVER",hostname);
						sprintf(reckey, "%s%d.%d.%d.%d-%d;%d.%d.%d.%d", dir, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4,
							dport, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
						sprintf(remoteaddr, "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
					 
						updateconvlist(RECEIVE,reckey, remoteaddr, dport,tcppayload_len);
						
				}
				else
				{
					if (isserverport(dport))
					{
						sprintf(dir, "%s;%s;", "SERVER",hostname);
						sprintf(reckey, "%s%d.%d.%d.%d-%d;%d.%d.%d.%d", dir, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4,
							dport, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
						sprintf(remoteaddr, "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
					 
						updateconvlist(RECEIVE,reckey, remoteaddr, dport,tcppayload_len);
					}
					else
					{
						sprintf(dir, "%s;%s;", "CLIENT",hostname);
						sprintf(reckey, "%s%d.%d.%d.%d;%d.%d.%d.%d-%d", dir, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4,
							ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, sport);
						sprintf(remoteaddr, "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
						 
						updateconvlist(RECEIVE,reckey, remoteaddr, dport,tcppayload_len);
					}
					sprintf(msg, "%s %d.%d.%d.%d-%d <= %d.%d.%d.%d-%d\n", dir, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4,
						dport, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, sport);
					logit(3, msg);
				}
 			}
			else
				 // Send 
			{
			if ((uh2->th_flags & TH_SYN) && (uh2->th_flags & TH_ACK))
				{
			 
					addserverport(sport);
					sprintf(dir, "%s;%s;", "SERVER",hostname);
							sprintf(sendkey, "%s%d.%d.%d.%d-%d;%d.%d.%d.%d", dir, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4,
								sport, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
							sprintf(remoteaddr, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
							updateconvlist(SEND,sendkey, remoteaddr, sport,tcppayload_len);
				}
				else
				{
					if ((uh2->th_flags & TH_RST) && (uh2->th_flags & TH_ACK))
					{
		 

					}
					else
					{
						if (uh2->th_flags == TH_SYN) {
							 
						 

						}
						if (isserverport(sport))

						{
							sprintf(dir, "%s;%s;", "SERVER",hostname);
							sprintf(sendkey, "%s%d.%d.%d.%d-%d;%d.%d.%d.%d", dir, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4,
								sport, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
							sprintf(remoteaddr, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
							updateconvlist(SEND,sendkey, remoteaddr, sport,tcppayload_len);
						}
						else
						{
							sprintf(dir, "%s;%s;", "CLIENT",hostname);
							sprintf(sendkey, "%s%d.%d.%d.%d;%d.%d.%d.%d-%d", dir, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4,
								ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, dport);
							sprintf(remoteaddr, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
						 
							updateconvlist(SEND,sendkey, remoteaddr, sport,tcppayload_len);
						}

						// for debugging
						sprintf(msg, "debug :%s  %d.%d.%d.%d-%d => %d.%d.%d.%d-%d\n", dir, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4,
							sport, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, dport);
						logit(3, msg);
					}
				}
			}
			break;
		case IPPROTO_UDP:
			return ;
			break;
		case IPPROTO_ICMP:
			return ;
			break;
		}
		

}

void* timerthread(void* args)
{
	struct timeval tmnow;
	struct tm* tm;
	char buf[30];
	char pcle[30];
	logit(0, (char*)"Timer thread is started ");
	while (1)
	{
 
			
		logit(0, (char*)"Timer thread is active\n ");
	 
		usleep(500000); 

	}

}

int listinterface(char* lookupip)
{
	struct ifconf ifc;
	struct ifreq ifr[10];
	char myip[16];
	char ip6str[128];
	int sd, ifc_num, addr, bcast, mask, network, i;
	int ret = -1;
	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd > 0)
	{
		ifc.ifc_len = sizeof(ifr);
		ifc.ifc_ifcu.ifcu_buf = (caddr_t)ifr;

		if (ioctl(sd, SIOCGIFCONF, &ifc) == 0)
		{
			ifc_num = ifc.ifc_len / sizeof(struct ifreq);
	 

			for (i = 0; i < ifc_num; ++i)
			{
				if (ifr[i].ifr_addr.sa_family != AF_INET)
				{
					continue;
				}

				 
				if (strstr(ifr[i].ifr_name, "lo") == NULL)
				{
					sprintf(msg, "selected :%s", ifr[i].ifr_name);
					logit(0, msg);
					if (ioctl(sd, SIOCGIFADDR, &ifr[i]) == 0)
					{
						addr = ((struct sockaddr_in*)(&ifr[i].ifr_addr))->sin_addr.s_addr;
			 	 
						sprintf(ip6str, "%d.%d.%d.%d", INT_TO_ADDR(addr));

						if (strcmp(ip6str, lookupip) == 0)
						{
							ret = 0;
							break;
						}

					}
				}
				/* Retrieve the IP address, broadcast address, and subnet mask. */
				if (ioctl(sd, SIOCGIFADDR, &ifr[i]) == 0)
				{
					addr = ((struct sockaddr_in*)(&ifr[i].ifr_addr))->sin_addr.s_addr;
					 
				}
				if (ioctl(sd, SIOCGIFBRDADDR, &ifr[i]) == 0)
				{
					bcast = ((struct sockaddr_in*)(&ifr[i].ifr_broadaddr))->sin_addr.s_addr;
					 
				}
				if (ioctl(sd, SIOCGIFNETMASK, &ifr[i]) == 0)
				{
					mask = ((struct sockaddr_in*)(&ifr[i].ifr_netmask))->sin_addr.s_addr;
					 
				}

				/* Compute the current network value from the address and netmask. */
				network = addr & mask;
			 
			}
		}

		close(sd);
	}
	return ret;
}
 

int gettcpserverport()
{
 
	FILE* tcp = fopen("/proc/net/tcp", "r");
	char* line = NULL;
	size_t n = 0;
	int i = 0;


	typedef union _iaddr {
		unsigned u;
		unsigned char b[4];
	} iaddr;
	unsigned int conn_state;
	unsigned lport, rport, state, txq, rxq, num, uid;
	unsigned long inode;
	iaddr laddr, raddr;
	char lip[ADDR_LEN] = { 0, }, rip[ADDR_LEN] = { 0, };
	uint32_t loop = atoi("127.0.0.1");
	struct sockaddr_in antelope;
	inet_aton("127.0.0.1", &antelope.sin_addr);
	i = 0;
	while OK(getline(&line, &n, tcp))

	{
		if (i = !0)
		{
			int nitems = sscanf(line, " %d: %x:%x %x:%x %x %x:%x %*X:%*X %*X %d %*d %ld",
				&num, &laddr.u, &lport, &raddr.u, &rport, &state, &txq,
				&rxq, &uid, &inode);

			if (nitems == 10) {
				 	
					if ( (state == 10) && (laddr.b[0]!= 127))
					{
				 		printf("Server port %d \n", lport);
						addserverport(lport);
					}
			}

		}
		i++;

	}

}
// 	

int main(int argc, char* argv[])
{
  
	 
 
	bool intrequested = false ;
	bool  intfound = false;
	
	char captureip[128];
	pcap_if_t* alldevs;
	pcap_if_t* device;
	pcap_addr_t* address;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t capturedevice;
	
	int pcap_snapshot_len = 1028;
	int pcap_promiscuous = 1	;
	int pcap_timeout = 1;
	int i;
	time(&starttime);
	//get local hostname  
	gethostname(hostname, HOST_NAME_MAX + 1);
	// initialize send , rec and conv list  
	initkeylist();
	// Add to serveport any port that are listening 
	gettcpserverport();
	 
	// process args set the verbosity and get dev bound with requested IP.
	logit(0, (char*)"Lnet is starting  V5.3 (excludes MS ports) \n");
  	i = 1;
	for ( i = 1; i < argc; i++) {
		if (strstr("-d", argv[i]))
				loglevel = atoi(argv[i + 1]);
		if (strstr("-n", argv[i]))
				resolvelevel = atoi(argv[i + 1]);
		if (strstr("-h", argv[i]))
				{
					durationinsec = 60*60*atoi(argv[i + 1]);
					
				}
		if (strstr("-f", argv[i]))
		{
			storeinfile = true;
			sprintf(outputpath, "%s", argv[i + 1]);
		}
		if (strstr("-i", argv[i]))
		{
			intrequested = true;
			sprintf(msg, "checking %s", argv[i + 1]);
			sprintf(mytargetip, "%s", argv[i + 1]);
			logit(0, msg);
			if (listinterface(argv[i + 1]))
			{
				sprintf(msg, "no interface bound with %s found . Hipnet ended", argv[i + 1]);
				logit(0, msg);
			}
			else
			{
				sprintf(msg, "interface bound with %s found\n", argv[i + 1]);
				logit(0, msg);
				if (pcap_findalldevs( &alldevs, pcap_errbuf) == -1)
				{
					fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", pcap_errbuf);
					exit(1);
				}
				for (device = alldevs; device != NULL; device= device->next)
				{
					for (address = device->addresses; address; address = address->next) {
						switch (address->addr->sa_family)
						{
						case AF_INET:
							if (address->addr)
							{
								int addr = ((struct sockaddr_in*)address->addr)->sin_addr.s_addr;
								sprintf(captureip, "%d.%d.%d.%d", INT_TO_ADDR(addr));
								if (strcmp(captureip, argv[i + 1]) == 0)
								{
									memcpy(&capturedevice, device, sizeof(pcap_if_t));
									sprintf(msg, "Found Interface %s\n", capturedevice.name);
									logit(0, msg);
									strcpy(mytargetip, argv[i + 1]);
									intfound=true;
 									break;
								}
							}
						}
						if (intfound)
							break;
 
					}
					if (intfound)
							break;

				}
			}
		}
	}
	 
	if (!intrequested)
	{
		printf("Please specify which IP address you want use : -i  \n ");
		return 0;
	}
	sprintf(msg, "Log level is %d\n", loglevel);
	logit(0,msg);
	sprintf(msg, "Resolve level is %d\n", resolvelevel);
	logit(0,msg);
	// initialize process tab  
	//initproent();
	// add process with Fd , inode in process tab 
	//addprocess();
	 

	handle = pcap_open_live(capturedevice.name, pcap_snapshot_len, pcap_promiscuous, pcap_timeout, pcap_errbuf);
	if (handle == NULL) {
		sprintf(msglong, "%s %s\n", capturedevice.name, pcap_errbuf);
		logit(0, msglong);
	}
	//sprintf(msg, "Pcap open device %s: %s\n", capturedevice.name, pcap_errbuf);
	//logit(3, msg);
	pcap_loop(handle, 0, my_packet_handler, NULL);
	strcat(outputpath,".DET");
	fOut = fopen(outputpath, "a");
				
			 
				
	for ( int k = 0; k < MAX_TCPCONV; k++)
	{
		 if (strncmp(convlist[k].key, nullblank,128) == 0) 
		 break;
		 dmsglong[0]='\0';
		 printf("%s;%ld;%ld;%s \n",convlist[k].key,convlist[k].nbpaketin,convlist[k].nbpaketout,convlist[k].retline);
		 sprintf(dmsglong,"%s;%ld;%ld;%s \n",convlist[k].key,convlist[k].nbpaketin,convlist[k].nbpaketout,convlist[k].retline);

		 fputs(dmsglong, fOut);
	}
	fclose(fOut);
	logit(0, (char*)"Lnet stopped");

	return 0;
}