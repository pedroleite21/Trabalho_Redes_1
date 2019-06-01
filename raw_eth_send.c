#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	char data[MAX_DATA_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

	short int hardtype = htons(0x0001);
	short int proptype = htons(0x0800);

	char hardsize[] = {htons(0x06)};
	char propsize[] = {htons(0x04)};

	short int operation = htons(0x0001);

	char orig_ip[] = {192, 168, 1, 187};
	char dest_ip[] = {0xFF, 0XFF, 0XFF, 0XFF};

	if (argc != 2)
	{
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0)
	{
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0)
	{
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);

	/* Preenche o campo hard type */
	memcpy(buffer + frame_len, &hardtype, sizeof(hardtype));
	frame_len += sizeof(hardtype);

	/* prop type */
	memcpy(buffer + frame_len, &proptype, sizeof(proptype));
	frame_len += sizeof(proptype);

	/* hard size */
	memcpy(buffer + frame_len, &hardsize, sizeof(hardsize));
	frame_len += sizeof(hardsize);

	/* prop size */
	memcpy(buffer + frame_len, &propsize, sizeof(propsize));
	frame_len += sizeof(propsize);

	/* op */
	memcpy(buffer + frame_len, &operation, sizeof(operation));
	frame_len += sizeof(operation);

	/* sender Ethernet addr */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* sender IP addr */
	memcpy(buffer + frame_len, orig_ip, sizeof(orig_ip));
	frame_len += sizeof(orig_ip);

	/* target Ethernet addr */
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	dest_ip[0] = orig_ip[0];
	dest_ip[1] = orig_ip[1];
	dest_ip[2] = orig_ip[2];
	dest_ip[3] = 0;

	while (dest_ip[3] < 255)
	{
		if (dest_ip[3] != = orig_ip[3])
		{
			/* target IP adr */
			memcpy(buffer + frame_len, dest_ip, sizeof(dest_ip));
			frame_len += sizeof(dest_ip);

			/* envia pacote */
			if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			{
				perror("send");
				close(fd);
				exit(1);
			}

			printf("Pacote enviado.\n");
		}

		dest_ip[3] = dest_ip[3] + 1;
	}

	close(fd);
	return 0;
}
