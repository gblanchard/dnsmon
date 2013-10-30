#include "config.h"

#include "dnsmon.h"

#include <sys/types.h>
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

int main(int argc, char *argv[])
{
	return 0;
}
