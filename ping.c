////
//// Created by manasabhilash on 4/14/20.
////
//
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <strings.h>
#include <time.h>
#include<signal.h>

#define HOSTNAME 1
#define IPV4 2
#define IPV6 3
#define INVALID 4

#define PACKETSIZE	64
struct packet
{
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

int pid = -1, cnt;
struct protoent *proto=NULL;
struct addrinfo *infoptr;
char* filename = "data.txt";

void sigHandler(int sig){
    int seq;
    float time;
    FILE *fp;
    fp  = fopen (filename, "r");
    fscanf(fp, "%d", &seq);
    fscanf(fp, "%f", &time);
    fclose(fp);
    double percent = 100*((double)(cnt-seq)/cnt);
    printf("\n----------UPING STATISTICS-------\n");
    printf("Packets Transmitted %d, Packets Recieved %d, Packet Loss %f%% Total Time : %f\n",cnt, seq, percent, time);
    if(cnt > 2){
	    printf("NOTE : The apparent packet loss of 2 packets is due to interrupt in processing\n");
    }
    freeaddrinfo(infoptr);
    remove(filename);	
    exit(0);
}

void display(void *buf, int bytes, long double *startTimes, clock_t endTime, clock_t start)
{
    int i;
    struct iphdr *ip = buf;
    struct icmphdr *icmp = buf+ip->ihl*4;
    clock_t n = endTime - start;
    double RTT = (double) n/(double)CLOCKS_PER_SEC;
    struct in_addr a;
    a.s_addr = ip->saddr;
    printf("64 bytes of data from %s IPv%d: hdr-size=%d pkt-size=%d protocol=%d TTL=%d ",inet_ntoa(a),
           ip->version, ip->ihl*4, ntohs(ip->tot_len), ip->protocol,
           ip->ttl);
    if ( icmp->un.echo.id == pid )
    {
        FILE *fp;
        char str[10];
        int seq;
        float time = 0;
        fp  = fopen ("data.txt", "r");
        fscanf(fp, "%d", &seq);
        fscanf(fp, "%f", &time);
        fclose(fp);
        float t = 1000000*RTT + time;
        sprintf(str, "%d %f %f",seq+1, t, time);
        fp  = fopen ("data.txt", "w+");
        fwrite(str , 1 , sizeof(str) , fp );
        fflush(fp);
        fclose(fp);
        printf("ICMP: type=%d/%d headr_checksum=%d id=%d icmp_seq=%d RTT=%fms\n",
               icmp->type, icmp->code, ntohs(icmp->checksum),
               icmp->un.echo.id, icmp->un.echo.sequence,1000000*RTT);
    }
}


int typeChecker(char* hostOrDest){
    struct sockaddr_in sa;
    struct sockaddr_in6 s;
    int result = inet_pton(AF_INET, hostOrDest, &(sa.sin_addr));
    if(result != 0) return IPV4;
    result = inet_pton(AF_INET6, hostOrDest, &(s.sin6_addr));
    if(result != 0) return IPV6;
    return HOSTNAME;
}

unsigned short checksum(void *b, int len)
{	unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void ping(struct addrinfo *addr, int ttl){
    long double arr[10000];
    clock_t startTime, endTime;
    const int val = ttl;
    int i, sd = -1, fd;
    cnt=1;
    struct packet pckt;
    struct sockaddr_in r_addr;
    for (struct addrinfo *p = addr; p != NULL; p = p->ai_next) {
            sd = socket(addr->ai_family, SOCK_RAW, proto->p_proto);
            fd = socket(addr->ai_family, SOCK_RAW, proto->p_proto);
            if(sd > 0) break;
    }
    if (sd < 0)
    {
        perror("socket");
        return;
    }
    if(addr->ai_family == AF_INET6){
        if(setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val)) != 0)
            perror("Set TTL option");
    }else {
        if (setsockopt(fd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0)
            perror("Set TTL option");
    }
    if ( fcntl(fd, F_SETFL, O_NONBLOCK) != 0 )
        perror("Request nonblocking I/O");
    if(addr->ai_family == AF_INET6){
        if(setsockopt(sd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val)) != 0)
            perror("Set TTL option");
    }else {
        if (setsockopt(sd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0)
            perror("Set TTL option");
    }
    if ( fcntl(sd, F_SETFL, O_NONBLOCK) != 0 )
        perror("Request nonblocking I/O");
    for (;;)
    {	int len=sizeof(r_addr);
        int bytes;
        if ( bytes = recvfrom(fd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &len) > 0 && ((endTime = clock())) ){
                display(&pckt, bytes, arr, endTime, startTime);
        }
        bzero(&pckt, sizeof(pckt));
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = pid;
        for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
            pckt.msg[i] = i+'0';
        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = cnt++;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
        if ((sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr->ai_addr, sizeof(*addr->ai_addr)) <= 0))
            perror("sendto");
        startTime = clock();
        arr[cnt-1] = (long double) startTime;
        sleep(1);
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, sigHandler);
    struct addrinfo hints, *infoptr;
    struct sockaddr_in addr;
    int seq;
    double time;
    FILE *fp;
    fp  = fopen(filename, "w");
    fprintf(fp,"%d %f",0,0);
    fclose(fp);
    int inputType = -1;
    int ttl = 255;

    if(argc != 2 && argc != 4){
        printf("UPING Usage : uping [-t ttl] [hostname|destination]\n"); fflush(stdout);
        exit(0);
    }
    if(argc == 4 && strcmp(argv[1],"-t") == 0) ttl = atoi(argv[2]);

    inputType = typeChecker(argv[argc-1]);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = getprotobyname("ICMP")->p_proto;
    hints.ai_flags = 0;
    int result = getaddrinfo(argv[argc-1], NULL, &hints, &infoptr);
    if (result) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        exit(1);
    }
    pid = getpid();
    proto = getprotobyname("ICMP");
    printf("UPING %s 64 bytes of data\n",argv[argc-1]);
    ping(infoptr, ttl);
    return 0;
}
