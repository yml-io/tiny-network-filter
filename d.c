/*
  ifconfig eth0 promisc
gcc `libnet-config --defines` d.c -o d `libnet-config --libs` -lnet
*/
#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>


#define MAXRULER  10

#define HASHTABLESIZE  30

/* 接收缓冲区大小 */
#define RCV_BUF_SIZE  1024 * 5

/* 接收缓冲区 */
static int g_iRecvBufSize = RCV_BUF_SIZE;
static char g_acRecvBuf[RCV_BUF_SIZE] = {0};

/* 物理网卡接口,需要根据具体情况修改 */
char g_szIfName[255];

struct RulerItem{
char StatusCode[4];
char Url[255];
char Host[255];
char TargetUrl[256];
char FullPath[255];
};
struct htItem{
int index;
struct htItem* next;
};
struct RulerItem RI[MAXRULER];
struct htItem	htRuler[HASHTABLESIZE]= {0};
int RI_INDEX = 0;


/* 以太网帧封装的协议类型 
static const int      g_iEthProId[] = { ETHERTYPE_PUP,
                                        ETHERTYPE_SPRITE,
                                        ETHERTYPE_IP,
                                        ETHERTYPE_ARP,
                                        ETHERTYPE_REVARP,
                                        ETHERTYPE_AT,
                                        ETHERTYPE_AARP,
                                        ETHERTYPE_VLAN,
                                        ETHERTYPE_IPX,
                                        ETHERTYPE_IPV6,
                                        ETHERTYPE_LOOPBACK
                                      };
static const char g_szProName[][24] = { "none", "xerox pup", "sprite", "ip", "arp",
                                        "rarp", "apple-protocol", "apple-arp",
                                        "802.1q", "ipx", "ipv6", "loopback"
                                      };


 输出MAC地址 
static void ethdump_showMac(const int iType, const char acHWAddr[])
{
    int i = 0;

    if (0 == iType)
    {
        printf("SMAC=[");
    }
    else
    {
        printf("DMAC=[");
    }

    for(i = 0; i < ETHER_ADDR_LEN - 1; i++)
    {
        printf("%02x:", *((unsigned char *)&(acHWAddr[i])));
    }
    printf("%02x] ", *((unsigned char *)&(acHWAddr[i])));
}
*/
/* 物理网卡混杂模式属性操作 */
static int ethdump_setPromisc(const char *pcIfName, int fd, int iFlags)
{
    int iRet = -1;
    struct ifreq stIfr;

    /* 获取接口属性标志位 */
    strcpy(stIfr.ifr_name, pcIfName);
    iRet = ioctl(fd, SIOCGIFFLAGS, &stIfr);
    if (0 > iRet)
    {
        perror("[Error]Get Interface Flags");   
        return -1;
    }
   
    if (0 == iFlags)
    {
        /* 取消混杂模式 */
        stIfr.ifr_flags &= ~IFF_PROMISC;
    }
    else
    {
        /* 设置为混杂模式 */
        stIfr.ifr_flags |= IFF_PROMISC;
    }

    iRet = ioctl(fd, SIOCSIFFLAGS, &stIfr);
    if (0 > iRet)
    {
        perror("[Error]Set Interface Flags");
        return -1;
    }
   
    return 0;
}


/* Init L2 Socket */
static int ethdump_initSocket()
{
    int iRet = -1;
    int fd = -1;
    struct ifreq stIf;
    struct sockaddr_ll stLocal = {0};
   
    /* 创建SOCKET */
    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (0 > fd)
    {
        perror("[Error]Initinate L2 raw socket");
        return -1;
    }
   
    /* 网卡混杂模式设置 */
    ethdump_setPromisc(g_szIfName, fd, 1);

    /* 设置SOCKET选项 */
    iRet = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &g_iRecvBufSize,sizeof(int));
    if (0 > iRet)
    {
        perror("[Error]Set socket option");
        close(fd);
        return -1;
    }
   
    /* 获取物理网卡接口索引 */
    strcpy(stIf.ifr_name, g_szIfName);
    iRet = ioctl(fd, SIOCGIFINDEX, &stIf);
    if (0 > iRet)
    {
        perror("[Error]Ioctl operation");
        close(fd);
        return -1;
    }

    /* 绑定物理网卡 */
    stLocal.sll_family = PF_PACKET;
    stLocal.sll_ifindex = stIf.ifr_ifindex;
    stLocal.sll_protocol = htons(ETH_P_ALL);
    iRet = bind(fd, (struct sockaddr *)&stLocal, sizeof(stLocal));
    if (0 > iRet)
    {
        perror("[Error]Bind the interface");
        close(fd);
        return -1;
    }
   
    return fd;   
}


/* get GET *** HTTP/1.* \r\n segment */
char *getGetUrl(char *firline)
{
	char *p, *q;
	int i;
	while( *(firline + i) != '\r' && i < 268 ){
	//printf("%c",*(pp + i));
	i ++;
	}
	if( i == 268 ){
		*(firline + i) = '\0';
		if( (p = strstr(firline, "GET ")) !=NULL && (q = strstr(firline, " HTTP/")) !=NULL ){
			p += strlen("GET ");
			*(q) = '\0';
			return p;
		}
	return NULL;
	}
	return NULL;
}

/* 解析IP数据包头 */
static int ethdump_parseIpHead(const struct ip *pstIpHead)
{
    struct protoent *pstIpProto = NULL;

    if (NULL == pstIpHead)
    {
        return -1;
    }

    /* 协议类型、源IP地址、目的IP地址 */
    pstIpProto = getprotobynumber(pstIpHead->ip_p);
    if(NULL != pstIpProto)
    {
        printf(" IP-Pkt-Type:%d(%s) ", pstIpHead->ip_p, pstIpProto->p_name);
    }
    else
    {
        printf(" IP-Pkt-Type:%d(%s) ", pstIpHead->ip_p, "None");
    }
    printf("SAddr=[%s] ", inet_ntoa(pstIpHead->ip_src));
    printf("DAddr=[%s] \n", inet_ntoa(pstIpHead->ip_dst));

char *pp = (char *)(pstIpHead) + sizeof(struct ip) + 20; ///////////////////
char *geturl;
if( (geturl = getGetUrl(pp)) != NULL ){
//printf("%s\n", geturls);
return 0;
}

    return -1;
}



//READ FROM CONFIG FILE
int readconf()
{
	int success = 1, i;
	char filename[] = "COMMON.CONFIG"; 
	FILE *fp; 
	char StrLine[1024]; 

	char *p, *q;
	do{
	if((fp = fopen(filename,"r")) == NULL){ success = 0; break; } 
	while (!feof(fp)) 
	{
		fgets(StrLine,1024,fp);  
		i = 0;
		while(isspace(StrLine[i]) && StrLine[i] != '\0')i++;
		if(StrLine[i] == '\0' || StrLine[i] == '#') continue;
		if( (p = strstr(&StrLine[i], "HostPort")) != NULL && (q = strstr(&StrLine[i], "/HostPort")) != NULL){
			p = p + strlen("HostPort>");
			q--;
			*q = '\0';
			memcpy(g_szIfName, p, strlen(p)+1);
printf("HostPort : %s\n", g_szIfName);
		}
	} //while(!feof(fp))
	fclose(fp); 

	}while(0);

	return success;
}

//FILTER RULER
int readruler()
{
	int success = 1, i;
	char filename[] = "RULER.CONFIG"; 
	FILE *fp; 
	char StrLine[1024], StatusCode[5], filUrl[255], filHost[255], filTarget[255]; 
	memset(RI, 0, sizeof(struct RulerItem) * MAXRULER);
	char *p, *q;
	do{
	if((fp = fopen(filename,"r")) == NULL){ success = 0; break; } 
	while (!feof(fp)) 
	{ 
		fgets(StrLine,1024,fp);  
		i = 0;
		while(isspace(StrLine[i]) && StrLine[i] != '\0')i++;
		if(StrLine[i] == '\0' || StrLine[i] == '#') continue;
		if( (p = strstr(&StrLine[i], "STATUSCODE")) != NULL && (q = strstr(&StrLine[i], "/STATUSCODE")) != NULL){
		//statuscode
			p = p + strlen("STATUSCODE>");
			q--;
			*q = '\0';
			memcpy(StatusCode, p, strlen(p)+1);
		//url
		fgets(StrLine,1024,fp);
		if( (p = strstr(StrLine, "URL")) == NULL || (q = strstr(StrLine, "/URL")) == NULL){success = 0; break;}
			p = p + strlen("URL>");
			q--;
			*q = '\0';
			//find first "/"
			char * t = p;
			while(t != q && *t != '/')t++;
			*t = '\0';			
			memcpy(filHost, p, strlen(p)+1);
			if(t == q || (t + 1) == q)memcpy(filUrl, "/", 2);
			else{
				memcpy(filUrl, "/", 2);
				strcat(filUrl, t + 1);		
			}
			
		//target
		fgets(StrLine,1024,fp);
		if( (p = strstr(StrLine, "TARGET")) == NULL || (q = strstr(StrLine, "/TARGET")) == NULL){success = 0; break;}
			p = p + strlen("TARGET>");
			q--;
			*q = '\0';
			memcpy(filTarget, p, strlen(p)+1);
		//printf("%s||%s||%s\n", StatusCode, filUrl, filTarget);
		memcpy(RI[RI_INDEX].StatusCode, StatusCode, strlen(StatusCode) + 1);		
		memcpy(RI[RI_INDEX].Host, filHost, strlen(filHost) + 1);
		memcpy(RI[RI_INDEX].Url, filUrl, strlen(filUrl) + 1);
		memcpy(RI[RI_INDEX].TargetUrl, filTarget, strlen(filTarget) + 1);
		memcpy(RI[RI_INDEX].FullPath, RI[RI_INDEX].Host, strlen(RI[RI_INDEX].Host) + 1);
		strcat(RI[RI_INDEX].FullPath, RI[RI_INDEX].Url);
		RI_INDEX ++;
		}
	} //while(!feof(fp))
	fclose(fp); 

	}while(0);

	return success;
}

int hashfun(char *buff)
{
		long sum = 0, hashcode = 0, j;
		for(j = 0; j <= strlen(buff) - 4; j += 4){
				sum +=	*((int *)(buff + j));
		}
		hashcode = sum % HASHTABLESIZE;
		return hashcode;
}

int sortruler()
{
//use RIITEM.url + RIITEM.host value as hash index
	char urlbuff[256] = {0};
	int i, j, sum, hashcode;
	struct htItem * nh, *p;
	memset(htRuler, 0, sizeof(struct htItem) * HASHTABLESIZE);
	for(i = 0; i < RI_INDEX; i++){
		sum = 0;
		memset(urlbuff, 0, sizeof(urlbuff));
		memcpy(urlbuff, RI[i].Host, strlen(RI[i].Host));
		strcat(urlbuff, RI[i].Url);
		hashcode = hashfun(urlbuff);

		//insert into hashtable
		nh = (struct htItem*)malloc(sizeof(struct htItem));
		if(nh == NULL){printf("NO HAVE ENOUGH MEM TO ALLOCATE!\n");exit(-1);}
		nh -> index = i;
		nh -> next = NULL;
		printf("first put %d in hashtable[%d]\n", i, hashcode);
		if(htRuler[hashcode].next == NULL){
			htRuler[hashcode].next = nh;
			
		}else{
			p = htRuler[hashcode].next;
			while(p -> next!= NULL)p = p -> next;
			p ->next = nh;		
		}
	}
	return 0;
}

/* verify the url  */
struct RulerItem* verifyUrl(char *httpbuf)
{
	char urlbuff[256] = {0};
	//find Host string
	int index = 0, rear, hashcode;
	while( *((int *)(httpbuf + index)) != 0x74736f48 && *((int *)(httpbuf + index)) != 0x0a0d0a0d && index < 300)index ++;/* "Host" "/r/n" hexcode , maximum try limit 300 */
	if( *((int *)(httpbuf + index)) == 0x74736f48 ){
		rear = index + 5; //skip "Host:"
		while( *(httpbuf + rear) == ' ' )rear ++;
		index = rear;
		while( *(httpbuf + rear) != '\r' && rear < 255)rear ++;//not exist length large than 255 char Host
		if(*(httpbuf + rear) == '\r'){
			*(httpbuf + rear) = '\0';
			memcpy(urlbuff, httpbuf + index, strlen(httpbuf + index) + 1);
			strcat(urlbuff, httpbuf);
			hashcode = hashfun(urlbuff);
			//printf("user full url is %s\n", urlbuff);
			struct htItem *htp;
			htp = htRuler[hashcode].next;
			while(htp != NULL){
				int compstrlen = strlen(RI[htp -> index].FullPath);
printf("Compare %s and %s\n",RI[htp -> index].FullPath, urlbuff );
				if(memcmp(RI[htp -> index].FullPath, urlbuff, compstrlen) == 0){return &RI[htp -> index];}else htp = htp -> next;
			}
			return NULL;
		}
		return NULL;
	}
	return NULL;	
}


char http302header[300] = "HTTP/1.1 302 Found\r\nServer: RDSys\r\nContent-Type: text/html\r\nConnection: close\r\nLocation: ";
int http302hdrLen = 0; //not include '\0'
/* send 302 packet */
int send302Packet(char *pcFrameData, struct RulerItem * hti)
{
    int c;
    char *cp;
    libnet_t *l;
    libnet_ptag_t t;
    char *payload;
    u_short payload_s;
    u_long src_ip, dst_ip;
    u_short src_prt, dst_prt;
    char errbuf[LIBNET_ERRBUF_SIZE];


    l = libnet_init(
            LIBNET_RAW4,                            /* injection type */
            NULL,                                   /* !!!!!!!!!!!!!!!!!!!!!network interface */
            errbuf);                                /* error buffer */

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE); 
    }
    
    struct ip * ipsegment = (struct ip*)pcFrameData;
    struct tcphdr* tcpsegment = (struct tcphdr*)(ipsegment + 1);
    src_ip  = *((u_long*)((char*)ipsegment + 16)) ;
    dst_ip  = *((u_long*)((char*)ipsegment + 12));
    src_prt = ntohs(tcpsegment -> th_dport);
    dst_prt = ntohs(tcpsegment -> th_sport);
    memcpy(http302header + http302hdrLen, hti -> TargetUrl, strlen(hti -> TargetUrl) + 1);
    strcat(http302header, "\r\nContent-Length: 0\r\n\r\n");
    payload = http302header;
    payload_s = strlen(http302header);
                                       
    t = libnet_build_tcp(
        src_prt,                                    /* source port */
        dst_prt,                                    /* destination port */
        ntohl(tcpsegment -> th_ack),                                 /* sequence number */
        ntohl(tcpsegment -> th_seq) + 288,       /* acknowledgement num !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
        TH_ACK | TH_PUSH,                                     /* control flags */
        32767,                                      /* window size */
        0,                                          /* checksum */
        0,                                          /* urgent pointer */
        LIBNET_TCP_H + 20 + payload_s,              /* TCP packet size */
	(uint8_t*)payload,                         /* payload */
        payload_s,                                  /* payload size */
        l,                                          /* libnet handle */
        0);                                         /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
        goto bad;
    }
	
    t = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,/* length */
      	0,                                          /* TOS */
        0xfff0,                                        /* IP ID */
        0,                                          /* IP Frag */
        128,                                         /* TTL */
        IPPROTO_TCP,                                /* protocol */
        0,                                          /* checksum */
        src_ip,                                     /* source IP */
        dst_ip,                                     /* destination IP */
        NULL,                                       /* payload */
        0,                                          /* payload size */
        l,                                          /* libnet handle */
        0);                                         /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        goto bad;
    }


    c = libnet_write(l);
    if (c == -1)
    {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
        goto bad;
   }
   else
   {	c = libnet_write(l);
       fprintf(stderr, "Wrote %d byte TCP packet; check the wire.\n", c);
   }

    libnet_destroy(l);
    return (EXIT_SUCCESS);
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);


}

/* 数据帧解析函数 ,the http head has found of "GET "  */
static int ethdump_parseFrame( char *pcFrameData)
{
	int i = 0, start;
	struct RulerItem* hti;
	while( *(pcFrameData + i) == ' ')i++; //skip " "	//can del??
	start = i;
	//while( *(pcFrameData + i) != ' ' && *(pcFrameData + i) != '?' && i < 256)i++;//find the string terminator
	while( *(pcFrameData + i) != ' ' && i < 256)i++;
	if(i < 256){
		*(pcFrameData + i) = '\0';
//printf("user url is %s\n", pcFrameData + start);
		if( (hti = verifyUrl(pcFrameData + start)) != NULL)
			send302Packet(pcFrameData - (sizeof(struct ip) + sizeof(struct tcphdr) + 4), hti);  //roll back http pointer to ip header			

	}
}

/* 捕获网卡数据帧 */
static void ethdump_startCapture(const int fd)
{
    int iRet = -1;
    socklen_t stFromLen = 0;
   
    /* 循环监听 */
    while(1)
    {
        /* 清空接收缓冲区 */
        memset(g_acRecvBuf, 0, RCV_BUF_SIZE);

        /* 接收数据帧 */
        iRet = recvfrom(fd, g_acRecvBuf, g_iRecvBufSize, 0, NULL, &stFromLen);
        if (0 > iRet)
        {
            continue;
        }
       
//printf("%d\n", *((int *)(g_acRecvBuf + sizeof(struct ether_header) + sizeof(struct ip) + struct tcphdr)));
        /* 解析数据帧 */
	if( *((int *)(g_acRecvBuf + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr))) == 0x20544547  )   //FIND STRING "GET ", not consider "Get " and "get "!!
        ethdump_parseFrame(g_acRecvBuf + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + 4 ); //skip "GET "
    }
}   

/* Main */
int main(int argc, char *argv[])
{
    int iRet = -1;
    int fd   = -1;
    
    http302hdrLen = strlen(http302header) ; //optimiztic


    /* READ RULER FILE */
	readconf();


    /* READ RULER FILE */
	readruler();

    /* 初始化SOCKET */
    fd = ethdump_initSocket();
    if(0 > fd)
    {
        return -1;
    }

/* DEBUG
int i ;
for(i = 0; i< RI_INDEX;i ++){
printf("%s|%s|%s|%s\n", RI[i].FullPath, RI[i].Url, RI[i].Host, RI[i].TargetUrl);
}
*/
	sortruler();
/* DEBUG */
int i;
struct htItem *p;
for(i = 0; i < HASHTABLESIZE; i++){
printf("%d: ", i);
p = htRuler[i].next;
while(p != NULL){printf("%d ", p->index);p = p -> next;}
printf("\n");
}
/* DEBUG */

    /* 捕获数据包 */
    ethdump_startCapture(fd);
   
    /* 关闭SOCKET */
    close(fd);

    return 0;
}
