#pragma once

/*
@brief structure pour stocker les informations des streams TCP (pour pouvoir identifier les paquets appartenant à un même stream et reconstituer un message complet)
*/
/*typedef struct ipv4_tcp_stream {
    int id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    u_char *data = NULL;
    int data_len;
    uint32_t expected_seq;
} ipv4_tcp_stream;

typedef struct ipv6_tcp_stream {
    int id;
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    u_char *data;
    int data_len;
    uint32_t expected_seq;
} ipv6_tcp_stream;*/


void analyse_UDP(const u_char *trame_UDP, int *longueur_restante_trame, int *longueur_restante_paquet);
void analyse_TCP(const u_char *packet, int *longueur_restante_trame, int *longueur_restante_paquet);
void analyse_ICMP(const u_char *packet, int *longueur_restante_trame, int *longueur_restante_paquet);
void analyse_ICMPv6(const u_char *packet, int *longueur_restante_trame, int *longueur_restante_paquet);