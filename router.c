#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int arp_table_len = 0;

/* A strucure who represent the node tree */
typedef struct trie_node {
	struct trie_node *left;
	struct trie_node *right;
	struct route_table_entry *route;
} trie_node;

/* List who store the packet what need a mac address */
typedef struct list_node {
	char* old_packet;
	int interface;
	int len;
	uint32_t ip;
	struct list_node *next;
} list_node;

/* Function who create a new element in list*/
list_node *create_node_list() {
	list_node *node = malloc(sizeof(list_node));
	node->old_packet = NULL;
	node->interface = 0;
	node->ip = 0;
	node->len = 0;
	node->next = NULL;
	return node;
}

/* Function who insert a new element in list */
void insert_list(list_node *head, char *old_packet, int interface, uint32_t ip, int len) {
	list_node *current = head;
	while (current->next != NULL) {
		current = current->next;
	}
	current->next = create_node_list();
	current = current->next;
	current->old_packet = old_packet;
	current->interface = interface;
	current->len = len;
	current->ip = ip;
}

/* Function who create a new node in trie */
trie_node *create_node() {
	trie_node *node = malloc(sizeof(trie_node));
	node->left = NULL;
	node->right = NULL;
	node->route = NULL;
	return node;
}

/* Function who insert a new route in trie */
void insert_in_trie(trie_node *root, struct route_table_entry *route) {
	uint32_t bite = 1 << 31;
	trie_node *current = root;

	// Iterate through the bits of the mask
	while ((ntohl(route->mask) & bite) != 0) {
		// If the bit is set go right else go left
		if ((ntohl(route->prefix) & bite) != 0) {

			if (current->right == NULL)
				current->right = create_node();

			current = current->right;
		} else {
			if (current->left == NULL)
				current->left = create_node();

			current = current->left;
		}
		bite = bite >> 1;
	}
	current->route = route;
}

/* Function who search the best route in trie */
struct route_table_entry *search_best_route(trie_node *root, uint32_t ip) {
	uint32_t bite = 1 << 31;
	trie_node *current = root;
	struct route_table_entry *best_route = NULL;
	
	// Iterate through the bits of the mask
	while (bite != 0) {
		// If the bit is set go right else go left
		if ((ip & bite) != 0) {

			if (current->right == NULL)
				return current->route;

			current = current->right;
		} else {

			if (current->left == NULL)
				return current->route;

			current = current->left;
		}
		bite = bite >> 1;
	}
	return best_route;
}

/* Function who get the mac address of an interface from cach*/
struct arp_table_entry *get_mac_entry(uint32_t given_ip , struct arp_table_entry *mac_table, int mac_table_len) {
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip) {
			return &mac_table[i];
		}
	}
	return NULL;
}

/* Function who create a arp request */
char* arp_request_populate(char *buf, int interface, uint32_t ip) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	eth_hdr->ether_type = htons(0x0806);
	get_interface_mac(interface, eth_hdr->ether_shost);
	memset(eth_hdr->ether_dhost, 0xff, 6);

	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	get_interface_mac(interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	memset(arp_hdr->tha, 0, 6);
	arp_hdr->tpa = ip;

	return buf;
}

/* Function who create a arp reply */
char* arp_reply_populate(char *buf, int interface, char *old_buf) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct ether_header *old_eth_hdr = (struct ether_header *)old_buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	struct arp_header *old_arp_hdr = (struct arp_header *)(old_buf + sizeof(struct ether_header));

	eth_hdr->ether_type = htons(0x0806);
	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, 6);

	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(2);
	get_interface_mac(interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	memcpy(arp_hdr->tha, old_arp_hdr->sha, 6);
	arp_hdr->tpa = old_arp_hdr->spa;

	return buf;
}

/* Function who create a icmp package */
char *icmp_populate(char *buf,int interface, struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t type) {
	struct ether_header *icmp_eth_hdr = (struct ether_header *)buf;
	struct iphdr *icmp_ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	icmp_eth_hdr->ether_type = htons(0x0800);
	memcpy(icmp_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, icmp_eth_hdr->ether_shost);

	icmp_ip_hdr->ihl = 5;
	icmp_ip_hdr->version = 4;
	icmp_ip_hdr->tos = 0;
	icmp_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	icmp_ip_hdr->id = htons(1);
	icmp_ip_hdr->frag_off = 0;
	icmp_ip_hdr->ttl = 64;
	icmp_ip_hdr->protocol = 1;
	icmp_ip_hdr->check = htons(checksum((uint16_t *)icmp_ip_hdr, sizeof(struct iphdr)));
	icmp_ip_hdr->saddr = ip_hdr->daddr;
	icmp_ip_hdr->daddr = ip_hdr->saddr;

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	return buf;
}

/* Function who add a new entry in arp table (cache) */
void add_arp_table(struct arp_table_entry *arp_table, uint32_t ip, uint8_t *mac) {
	arp_table[arp_table_len].ip = ip;
	memcpy(arp_table[arp_table_len].mac, mac, 6);
	arp_table_len++;
}


int main(int argc, char *argv[])
{
	int rtable_size;
	char buf[MAX_PACKET_LEN];

	struct route_table_entry *rtable;
	struct arp_table_entry *arp_table;

	list_node *head = create_node_list();

	init(argc - 2, argv + 2);
	
	// Create the routing table and the ARP table
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	arp_table = malloc(sizeof(struct arp_table_entry) * 10);
	DIE(rtable == NULL, "rtable malloc failed");

	// Read the routing table
	rtable_size = read_rtable(argv[1], rtable);
	DIE(rtable_size < 0, "read_rtable error");

	// Create the trie and insert evry route in it
	trie_node *root = create_node();
	for (int i = 0; i < rtable_size; i++) {
		insert_in_trie(root, &rtable[i]);
	}

	while (1) {
		int interface;
		size_t len;		
		struct route_table_entry *best_router;

		// Receive packets from any interface
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// Extract the ethernet header
		struct ether_header *eth_hdr = (struct ether_header *)buf;

		// Extract the ARP header if exists
		long arp_request_size = sizeof(struct ether_header) + sizeof(struct arp_header);
		struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
		char *arp_package = malloc(arp_request_size);

		// Get the IP of the router
		uint32_t route_ip = inet_addr(get_interface_ip(interface));
		
		// Check if the packet is an ipv4 packet
		if (ntohs(eth_hdr->ether_type) == 0x0800) {
			
			// Extract the IP header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// Check if the checksum is correct
			if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
				printf("Checksums do not match\n");
				continue;
			}
			
			// Check if the packet is for the router
			if (ip_hdr->daddr == route_ip) {
				long icmphdr_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				char *icmp_package = malloc(icmphdr_size);
				icmp_package = icmp_populate(icmp_package, interface, eth_hdr, ip_hdr, 0);

				send_to_link(interface, icmp_package, icmphdr_size);
				continue;
			}

			// Seach the best route for the packet, if don't find a route send a icmp package
			best_router = search_best_route(root, ntohl(ip_hdr->daddr));
			if (best_router == NULL) {
				long icmphdr_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				char *icmp_package = malloc(icmphdr_size);
				icmp_package = icmp_populate(icmp_package, interface, eth_hdr, ip_hdr, 3);

				send_to_link(interface, icmp_package, icmphdr_size);
				continue;
			}

			// If ttl expired send a icmp package
			if (ip_hdr->ttl <= 1) {
				long icmphdr_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				char *icmp_package = malloc(icmphdr_size);
				icmp_package = icmp_populate(icmp_package, interface,eth_hdr, ip_hdr, 11);

				send_to_link(interface, icmp_package, icmphdr_size);
				continue;	
			}

			// Update the ttl and calculate the new checksum
			uint16_t old_TTL = ip_hdr->ttl;
			uint16_t old_checksum = ip_hdr->check;
			ip_hdr->ttl--;

			ip_hdr->check = ~(~old_checksum + ~((uint16_t)old_TTL) + (uint16_t)ip_hdr->ttl) - 1;

			// Get the mac address of the next hop if don't find send a arp request
			struct arp_table_entry *mac_entry = get_mac_entry(best_router->next_hop, arp_table, arp_table_len);
			if (mac_entry == NULL) {
				char *new_buffer = malloc(len);
				memcpy(new_buffer, buf, len);
				arp_package = arp_request_populate(arp_package, best_router->interface, best_router->next_hop);

				insert_list(head, new_buffer, best_router->interface, best_router->next_hop, len);
				send_to_link(best_router->interface, arp_package, arp_request_size);
				continue;
			}
			
			memcpy(eth_hdr->ether_dhost, mac_entry->mac, 6);
			get_interface_mac(best_router->interface, eth_hdr->ether_shost);
			send_to_link(best_router->interface, buf, len);
		
		// Check if the packet is an arp packet
		} else if (ntohs(eth_hdr->ether_type) == 0x0806) {

			// Check if the packet is an arp request
			if (ntohs(arp_hdr->op) == 1) {
				// If the packet is for the router send a reply
				if(arp_hdr->tpa == route_ip){
					arp_package = arp_reply_populate(arp_package, interface, buf);
					send_to_link(interface, arp_package, arp_request_size);
					continue;
				}
			// Else if the packet is an arp reply
			} else if (ntohs(arp_hdr->op) == 2) {
				add_arp_table(arp_table, arp_hdr->spa, arp_hdr->sha);

				list_node *current = head;
				list_node *prev = head;

				// Search in the list the packets who need the mac address of the reply and send them
				while (current != NULL) {
					if (current->ip == arp_hdr->spa) {
						struct ether_header *old_eth_hdr = (struct ether_header *)current->old_packet;
						memcpy(old_eth_hdr->ether_dhost, arp_hdr->sha, 6);
						send_to_link(current->interface, current->old_packet, current->len);
						prev->next = current->next;

						free(current->old_packet);
						free(current);
					} else {
						prev = current;
					}
					current = current->next;
				}	
			}
		}
	}

	free(head);
	free(rtable);
	free(arp_table);
	return 0;
}
