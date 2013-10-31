#include "config.h"

#include "dnsmon.h"

#include <sys/types.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/in.h>

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netdb.h>

#include "hashtbl.h"
#include "inX_addr.h"

#define PCAP_SNAPLEN 65535
#define MAX_QNAME_SZ 512
#define DNS_MSG_HDR_SZ 12
#ifndef ETHER_HDR_LEN
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#endif
#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q 0x8100
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

#if defined(__linux__) || defined(__GLIBC__) || defined(__GNU__)
#define uh_dport dest
#define uh_sport source
#endif

#ifdef HAVE_STRUCT_BPF_TIMEVAL
struct bpf_timeval last_ts;
#else
struct timeval last_ts;
#endif

int promisc_flag = 1;
int check_interval = 5;
int do_report = 0;

char *device = NULL;
pcap_t *pcap = NULL;

//char *bpf_program_str = "udp port 53";
char *bpf_program_str = "(udp port 53) or (vlan and udp port 53)";
static unsigned short check_port = 0;

int (*handle_datalink) (const u_char * pkt, int len)= NULL;

unsigned int hash_buckets = 100057;
int opt_ipv4 = 0;
int opt_ipv6 = 0;

hashtbl *hashtable = NULL;

typedef struct {
    char *name;
    long long unsigned int count;
    long long unsigned int size;
} dns_response_t;

typedef struct {
    long long unsigned int size;
    void *ptr;
} sortitem_t;

int sortitem_cmp(const void *A, const void *B)
{
    sortitem_t *a = A;
    sortitem_t *b = B;

    if (a->size < b->size)
        return 1;
    if (a->size > b->size)
        return -1;
    if (a->ptr < b->ptr)
        return 1;
    if (a->ptr > b->ptr)
        return -1;

    return 0;
}

static unsigned int
string_hash(const void *s)
{
    return hashendian(s, strlen(s), 0);
}

static int
string_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

void dnsstring_free(void *p)
{
    dns_response_t *dns = p;
    free(dns->name);
    free(dns);
}

unsigned int my_inXaddr_hash(const void *key)
{
    return inXaddr_hash(key, 24);
}

int my_inXaddr_cmp(const void *a, const void *b)
{
    return inXaddr_cmp(a, b);
}

void cmdusage(void)
{
    fprintf(stderr, "usage: dnsmon [opts] netdevice|savefile\n");
    fprintf(stderr, "\t-4\tListen ipv4 packets\n");
    fprintf(stderr, "\t-6\tListen ipv6 packets\n");
    fprintf(stderr, "\t-b expr\tBPF filter\n");
    fprintf(stderr, "\t-v\tversion\n");
    fprintf(stderr, "\t-h\tthis help\n");
    exit(1);
}

void handle_pcap(u_char * udata, const struct pcap_pkthdr *hdr, const u_char * pkt)
{
    if (hdr->caplen < ETHER_HDR_LEN)
	    return;
    if (0 == handle_datalink(pkt, hdr->caplen))
	    return;
    last_ts = hdr->ts;
}

#define RFC1035_MAXLABELSZ 63
static int
rfc1035NameUnpack(const char *buf, size_t sz, off_t * off, char *name, size_t ns
)
{
    off_t no = 0;
    unsigned char c;
    size_t len;
    static int loop_detect = 0;
    if (loop_detect > 2)
    return 4;       /* compression loop */
    if (ns <= 0)
    return 4;       /* probably compression loop */
    do {
    if ((*off) >= sz)
        break;
    c = *(buf + (*off));
    if (c > 191) {
        /* blasted compression */
        int rc;
        unsigned short s;
        off_t ptr;
        memcpy(&s, buf + (*off), sizeof(s));
        s = ntohs(s);
        (*off) += sizeof(s);
        /* Sanity check */
        if ((*off) >= sz)
        return 1;   /* message too short */
        ptr = s & 0x3FFF;
        /* Make sure the pointer is inside this message */
        if (ptr >= sz)
        return 2;   /* bad compression ptr */
        if (ptr < DNS_MSG_HDR_SZ)
        return 2;   /* bad compression ptr */
        loop_detect++;
        rc = rfc1035NameUnpack(buf, sz, &ptr, name + no, ns - no);
        loop_detect--;
        return rc;
    } else if (c > RFC1035_MAXLABELSZ) {
        /*
         * "(The 10 and 01 combinations are reserved for future use.)"
         */
        return 3;       /* reserved label/compression flags */
        break;
    } else {
        (*off)++;
        len = (size_t) c;
        if (len == 0)
        break;
        if (len > (ns - 1))
        len = ns - 1;
        if ((*off) + len > sz)
        return 4;   /* message is too short */
        if (no + len + 1 > ns)
        return 5;   /* qname would overflow name buffer */
        memcpy(name + no, buf + (*off), len);
        (*off) += len;
        no += len;
        *(name + (no++)) = '.';
    }
    } while (c > 0);
    if (no > 0)
    *(name + no - 1) = '\0';
    /* make sure we didn't allow someone to overflow the name buffer */
    assert(no <= ns);
    return 0;
}


int handle_dns(const char *buf, int len,
    const inX_addr * src_addr,
    const inX_addr * dst_addr,
    unsigned short vlan)
{
    rfc1035_header qh;
    unsigned short us;
    char qname[MAX_QNAME_SZ];
    unsigned short qtype;
    unsigned short qclass;
    off_t offset;
    char *t;
    const char *s;
    int x;
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];

    if (len < sizeof(qh))
        return 0;

    memcpy(&us, buf + 00, 2);
    qh.id = ntohs(us);

    memcpy(&us, buf + 2, 2);
    us = ntohs(us);
    qh.qr = (us >> 15) & 0x01;
    qh.opcode = (us >> 11) & 0x0F;
    qh.aa = (us >> 10) & 0x01;
    qh.tc = (us >> 9) & 0x01;
    qh.rd = (us >> 8) & 0x01;
    qh.ra = (us >> 7) & 0x01;
    qh.rcode = us & 0x0F;

    if (qh.qr != 1)
        return 0;

    memcpy(&us, buf + 4, 2);
    qh.qdcount = ntohs(us);

    memcpy(&us, buf + 6, 2);
    qh.ancount = ntohs(us);

    memcpy(&us, buf + 8, 2);
    qh.nscount = ntohs(us);

    memcpy(&us, buf + 10, 2);
    qh.arcount = ntohs(us);

    offset = sizeof(qh);
    memset(qname, '\0', MAX_QNAME_SZ);
    x = rfc1035NameUnpack(buf, len, &offset, qname, MAX_QNAME_SZ);
    if (0 != x)
        return 0;
    
    if ('\0' == qname[0])
    strcpy(qname, ".");
    while ((t = strchr(qname, '\n')))
        *t = ' ';
    while ((t = strchr(qname, '\r')))
        *t = ' ';
    for (t = qname; *t; t++)
        *t = tolower(*t);

    memcpy(&us, buf + offset, 2);
    qtype = ntohs(us);
    memcpy(&us, buf + offset + 2, 2);
    qclass = ntohs(us);

    inXaddr_ntop(src_addr, src_str, sizeof(src_str));
    inXaddr_ntop(dst_addr, dst_str, sizeof(dst_str));

    //printf("qname = %s qr = %d len %d vlan %d %s %s\n", 
    //    qname, qh.qr, len, vlan, src_str, dst_str);

    dns_response_t *dns = hash_find(qname, hashtable);
    if (dns == NULL) {
        dns = calloc(1, sizeof(*dns));
        dns->name = strdup(qname);
        dns->count = 1;
        dns->size = len;
        hash_add(qname, dns, hashtable);
    } else {
        dns->count++;
        dns->size += len;
    }

    return 0;
}

int handle_udp(const struct udphdr *udp, int len,
    const inX_addr * src_addr,
    const inX_addr * dst_addr,
    unsigned short vlan)
{
    if (check_port && check_port != udp->uh_dport && check_port != udp->uh_sport)
	return 0;
    if (0 == handle_dns((char *)(udp + 1), len - sizeof(*udp), src_addr, dst_addr, vlan))
	return 0;
    return 1;
}

#if USE_IPV6
int handle_ipv6(struct ip6_hdr *ipv6, int len, unsigned short vlan)
{
    int offset;
    int nexthdr;

    inX_addr src_addr;
    inX_addr dst_addr;
    uint16_t payload_len;


    if (0 == opt_ipv6)
	return 0;

    offset = sizeof(struct ip6_hdr);
    nexthdr = ipv6->ip6_nxt;
    inXaddr_assign_v6(&src_addr, &ipv6->ip6_src);
    inXaddr_assign_v6(&dst_addr, &ipv6->ip6_dst);
    payload_len = ntohs(ipv6->ip6_plen);

    /*
     * Parse extension headers. This only handles the standard headers, as
     * defined in RFC 2460, correctly. Fragments are discarded.
     */
    while ((IPPROTO_ROUTING == nexthdr)	/* routing header */
	||(IPPROTO_HOPOPTS == nexthdr)	/* Hop-by-Hop options. */
	||(IPPROTO_FRAGMENT == nexthdr)	/* fragmentation header. */
	||(IPPROTO_DSTOPTS == nexthdr)	/* destination options. */
	||(IPPROTO_DSTOPTS == nexthdr)	/* destination options. */
	||(IPPROTO_AH == nexthdr)	/* destination options. */
	||(IPPROTO_ESP == nexthdr)) {	/* encapsulating security payload. */
	struct {
	    uint8_t nexthdr;
	    uint8_t length;
	}      ext_hdr;
	uint16_t ext_hdr_len;

	/* Catch broken packets */
	if ((offset + sizeof(ext_hdr)) > len)
	    return (0);

	/* Cannot handle fragments. */
	if (IPPROTO_FRAGMENT == nexthdr)
	    return (0);

	memcpy(&ext_hdr, (char *)ipv6 + offset, sizeof(ext_hdr));
	nexthdr = ext_hdr.nexthdr;
	ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

	/* This header is longer than the packets payload.. WTF? */
	if (ext_hdr_len > payload_len)
	    return (0);

	offset += ext_hdr_len;
	payload_len -= ext_hdr_len;
    }				/* while */

    /* Catch broken and empty packets */
    if (((offset + payload_len) > len)
	|| (payload_len == 0))
	return (0);

    if (IPPROTO_UDP != nexthdr)
	return (0);

    if (handle_udp((struct udphdr *)((char *)ipv6 + offset), payload_len, 
        &src_addr, &dst_addr, vlan) == 0)
	return (0);

    return (1);			/* Success */
}
#endif


int handle_ipv4(const struct ip *ip, int len, unsigned short vlan)
{
    int offset = ip->ip_hl << 2;
    inX_addr src_addr;
    inX_addr dst_addr;

#if USE_IPV6
    if (ip->ip_v == 6)
	return (handle_ipv6((struct ip6_hdr *)ip, len, vlan));
#endif

    if (0 == opt_ipv4)
	return 0;

    inXaddr_assign_v4(&src_addr, &ip->ip_src);
    inXaddr_assign_v4(&dst_addr, &ip->ip_dst);

    if (IPPROTO_UDP != ip->ip_p)
	return 0;
    if (0 == handle_udp((struct udphdr *)((char *)ip + offset), len - offset, 
        &src_addr, &dst_addr, vlan))
	return 0;
    return 1;
}

#ifdef DLT_RAW
int handle_raw(const u_char * pkt, int len)
{
    return handle_ipv4((struct ip *)pkt, len, 0);
}
#endif

int handle_ip(const u_char * pkt, int len, unsigned short vlan, unsigned short etype)
{
#if USE_IPV6
    if (etype == ETHERTYPE_IPV6) {
	return (handle_ipv6((struct ip6_hdr *)pkt, len, vlan));
    } else
#endif
    if (etype == ETHERTYPE_IP) {
	return handle_ipv4((struct ip *)pkt, len, vlan);
    }
    return 0;
}

int handle_ether(const u_char * pkt, int len)
{
    struct ether_header *e = (void *)pkt;
    unsigned short etype = ntohs(e->ether_type);
    if (len < ETHER_HDR_LEN)
	    return 0;
    pkt += ETHER_HDR_LEN;
    len -= ETHER_HDR_LEN;
    
    unsigned short vlan = 0;
    if (etype == ETHERTYPE_8021Q) {
        vlan = ntohs(*(unsigned short *)(pkt));
	    etype = ntohs(*(unsigned short *)(pkt + 2));
	    pkt += 4;
	    len -= 4;

    }
    return handle_ip(pkt, len, vlan, etype);
}

void dns_report(hashtbl *hash)
{
    int i;
    unsigned long long sum;
    double pps, kbps;
    dns_response_t *dns;
    int sortsize = hash_count(hash);
    sortitem_t *sortme = calloc(sortsize, sizeof(sortitem_t));

    hash_iter_init(hash);

    sortsize = 0;
    while ((dns = hash_iterate(hash))) {
        sum += dns->size;
        sortme[sortsize].size = dns->size;
        sortme[sortsize].ptr = dns;
        sortsize++;
    }
    
    qsort(sortme, sortsize, sizeof(sortitem_t), sortitem_cmp);
    
    for (i = 0;i < 10 && i < sortsize; i++) {
        dns = (dns_response_t *)(sortme + i)->ptr;

        pps = (double)dns->count / (double)check_interval;
        kbps = (double)dns->size / 1024.0 / (double)check_interval;

        printf("%d\t%s %0.2fkbps %0.2fpps\n", 
        i+1,
        dns->name,
        kbps,
        pps);
    }
    if (i > 0)
        printf("\n");

    hash_free(hashtable, dnsstring_free);
    hashtable = hash_create(hash_buckets, string_hash, string_cmp);
}

int
pcap_select(pcap_t * p, int sec, int usec)
{
    fd_set R;
    struct timeval to;
    FD_ZERO(&R);
    FD_SET(pcap_fileno(p), &R);
    to.tv_sec = sec;
    to.tv_usec = usec;
    return select(pcap_fileno(p) + 1, &R, NULL, NULL, &to);
}

void signal_timer(int sig)
{
    do_report = 1;
    signal(sig, signal_timer);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct stat sb;
    struct itimerval timer_itv;
    int daemon = 0;
    int readfile_state = 0;
    struct bpf_program fp;
    int x;

    while ((x = getopt(argc, argv, "46bdvh")) != -1) {
        switch (x) {
            case '4':
                opt_ipv4 = 1;
                break;
            case '6':
                opt_ipv6 = 1;
                break;
            case 'b':
                bpf_program_str = strdup(optarg);
            case 'v':
                fprintf(stderr, "dnsmon version 1.00\n");
                exit(0);
            case 'd':
                daemon = 1;
                break;
            case 'h':
                cmdusage();
                break;
            default:
                cmdusage();
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 1)
        cmdusage();

    device = strdup(argv[0]);

    if (!strstr(bpf_program_str, "port "))
        check_port = htons(53);

    // if ipv4 and ipv4 aint selected...select both
    if (opt_ipv4 == 0 && opt_ipv6 == 0)
        opt_ipv4 = opt_ipv6 = 1;

    if (stat (device, &sb) == 0)
        readfile_state = 1;

    if (readfile_state) {
        daemon = 0;
        pcap = pcap_open_offline(device, errbuf);
    } else {
        daemon = 1;
        pcap = pcap_open_live(device, PCAP_SNAPLEN, promisc_flag, 1, errbuf);
    }

    if (!pcap) {
        fprintf(stderr, "pcap_open_*: %s\n", errbuf);
        exit(1);
    }

    memset(&fp, 0, sizeof(fp));
    x = pcap_compile(pcap, &fp, bpf_program_str, 1, 0);
    if (x < 0) {
        fprintf(stderr, "pcap_compile failed: %s\n", bpf_program_str);
        exit(1);
    }
    x = pcap_setfilter(pcap, &fp);
    if (x < 0) {
        fprintf(stderr, "pcap_setfilter failed\n");
        exit(1);
    }

    pcap_setnonblock(pcap, 1, errbuf);

    switch (pcap_datalink(pcap)) {
        case DLT_EN10MB:
            handle_datalink = handle_ether;
            break;
        case DLT_RAW:
            handle_datalink = handle_raw;
            break;
        default:
            fprintf(stderr, "unsupported data link type %d\n",
                pcap_datalink(pcap));
            return 1;
            break;
    }

    hashtable = hash_create(hash_buckets, string_hash, string_cmp);

    if (daemon) {
        signal(SIGALRM, signal_timer);
        timer_itv.it_interval.tv_sec = check_interval;
        timer_itv.it_interval.tv_usec = 0;
        timer_itv.it_value.tv_sec = check_interval;
        timer_itv.it_value.tv_usec = 0;
        setitimer(ITIMER_REAL, &timer_itv, NULL);

        while (1) {
            pcap_select(pcap, 1, 0);
            x = pcap_dispatch(pcap, 50, handle_pcap, NULL);
            if (x != 0 && do_report) {
                do_report = 0;
                dns_report(hashtable);
            }
        }
    } else {

        while(pcap_dispatch(pcap, 1, handle_pcap, NULL)) {
        }
        dns_report(hashtable);
    }

    pcap_close(pcap);

    hash_free(hashtable, free);

    return 0;
}
