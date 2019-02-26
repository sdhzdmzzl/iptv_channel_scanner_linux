/*
 *
 * *iptvscanner.cpp - 多播的客户端
 *
 * */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int iptvscan(unsigned int ip)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    int s; /*套接字文件描述符*/
    int err = -1;

    s = socket(AF_INET, SOCK_DGRAM, 0); /*建立套接字*/
    if (s == -1)
    {
       return -1; 
    }

    struct ip_mreq mreq;                           /*加入多播组*/
    mreq.imr_multiaddr.s_addr = htonl(ip);         /*多播地址*/
    mreq.imr_interface.s_addr = htonl(INADDR_ANY); /*网络接口为默认*/

    err = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (err < 0)
    {
	return -1;
    }

    pcap_t *device = pcap_open_live("eno16780032", 65535, 1, 1, errBuf);//1ms超时，下边会留出时间填充数据包

    if (!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        close(s);
        return -1;
    }

    /* construct a filter */
    struct bpf_program filter;
    pcap_compile(device, &filter, "udp and net 239.3.1", 1, 0);
    pcap_setfilter(device, &filter);

    usleep(150000);
    struct pcap_pkthdr packet;
    const u_char *pktStr = pcap_next(device, &packet);
    if (pktStr)
    {
        struct iphdr *iphdr = NULL;
        struct udphdr *udphdr = NULL;
        iphdr = (struct iphdr *)(pktStr + 14);
        udphdr = (struct udphdr *)(pktStr + 14 + 20);
        printf("%s:%d\n", inet_ntoa(*(struct in_addr *)&iphdr->daddr), ntohs(udphdr->dest));
    }
    pcap_close(device);

    err = setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    if (err < 0)
    {
	close(s);
	return -1;
    }
    close(s);
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned int ip = ntohl(inet_addr("239.3.1.1"));
    for (int i = 0; i < 254; i++)
    {
        iptvscan(ip++);
    }
}
