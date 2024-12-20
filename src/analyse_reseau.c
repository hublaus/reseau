#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "bootp.h"
#include "analyse_reseau.h"
#include "analyse_transport.h"

void analyse_ipv4(const u_char *packet, int *longueur_restante_trame){

    //test avant cast pour éviter segmentation fault
    if (*longueur_restante_trame < 20){
        printf("Trame Ethernet trop courte pour contenir une entête ipv4, paquet erroné");
        return;
    }
    
    printf("\nAnalyse IPv4 : %d octets restants dans la trame", *longueur_restante_trame);
    const struct ip *ip;
    ip = (struct ip *) (packet + 14);   //14 = taille de l'entête ethernet (6 octets pour adresse MAC source, 6 octets pour adresse MAC destination, 2 octets pour type)
    printf("\n\tVersion IP: %d, ", ip->ip_v);
    printf("\n\tLongueur entête IP: %d, ", ip->ip_hl);
    printf("\n\tType de service: %d, ", ip->ip_tos);
    printf("\n\tLongueur totale: %hu, ", ntohs(ip->ip_len));
    printf("\n\tIdentifiant: %d, ", ntohs(ip->ip_id));
    printf("\n\tDécalage: %d, ", ntohs(ip->ip_off));
    printf("\n\tTTL: %d, ", ip->ip_ttl);
    printf("\n\tProtocole: 0x%02x, ", ip->ip_p);
    printf("\n\tChecksum: %d, ", ntohs(ip->ip_sum));
    printf("\n\tAdresse IP source: %s, ", inet_ntoa(ip->ip_src));
    printf("\n\tAdresse IP destination: %s, ", inet_ntoa(ip->ip_dst));
    printf("\n\tType de protocole transport : ");

    int longueur_paquet_restante = ntohs(ip->ip_len);   //nombre d'octets non encore lus dans le paquet IP 
                                //(pas forcément le nombre d'octets restant dans la trame, car octets de padding éventuels dans trame ethernet)


    //teste si la longueur du paquet IP est cohérente (ni négative ni plus grande que la longueur de la trame)
    if (longueur_paquet_restante < 0 || longueur_paquet_restante > *longueur_restante_trame){
        printf("Erreur : longueur payload IPv4 incorrecte, longueur paquet : %d, longueur trame : %d", longueur_paquet_restante, *longueur_restante_trame);
        return;
    }

    //Analyse ipv4 terminée, on passe à l'analyse du protocole de transport
    *longueur_restante_trame -= 4*ip->ip_hl; //4*ip->ip_hl = taille de l'entête IPv4
    longueur_paquet_restante -= 4*ip->ip_hl;

    if (ip->ip_p == IPPROTO_UDP){
        printf("UDP");
        analyse_UDP(packet+14+4*ip->ip_hl, longueur_restante_trame, &longueur_paquet_restante); //14 = taille en-tête ethernet, 4*ip->ip_hl = taille de l'entête IP
    }
    else if (ip->ip_p == IPPROTO_TCP){
        printf("TCP");
        analyse_TCP(packet+14+4*ip->ip_hl, longueur_restante_trame, &longueur_paquet_restante);
    }

    else if (ip->ip_p == IPPROTO_ICMP){
        printf("ICMP");
        analyse_ICMP(packet+14+4*ip->ip_hl, longueur_restante_trame, &longueur_paquet_restante);
    }
    
    else{
        printf("(Protocole transport non reconnu)");
    }
}


void analyse_ipv6(const u_char *packet, int *longueur_trame_restante){

    //test avant cast pour éviter segmentation fault
    if (*longueur_trame_restante < 40){
        printf("Trame Ethernet trop courte pour contenir une entête ipv6, paquet erroné");
        return;
    }

    printf("\nAnalyse IPv6 : ");
    const struct ip6_hdr *ip6;
    ip6 = (struct ip6_hdr *) (packet + 14);   //14 = taille de l'entête ethernet (6 octets pour adresse MAC source, 6 octets pour adresse MAC destination, 2 octets pour type)
    char str[INET6_ADDRSTRLEN];

    printf("\n\tVersion IP: %d, ", ip6->ip6_vfc >> 4);

    printf("\n\tClasse de trafic: %d, ",( (ntohl(ip6->ip6_flow)) >> 20 ) & 0x0ff);  //pour garder les bits 4 à 11
    printf("\n\tÉtiquette de flux: %d, ", ntohl(ip6->ip6_flow) & 0x000fffff);  //pour garder les bits 12 à 31
    printf("\n\tLongueur payload: %d, ", ntohs(ip6->ip6_plen));
    printf("\n\tEn-tête suivante: %d, ", ip6->ip6_nxt);
    printf("\n\tLimite de saut: %d, ", ip6->ip6_hlim);
    printf("\n\tAdresse IP source: %s, ", inet_ntop(AF_INET6, &(ip6->ip6_src), str, INET6_ADDRSTRLEN));
    printf("\n\tAdresse IP destination: %s, ", inet_ntop(AF_INET6, &(ip6->ip6_dst), str, INET6_ADDRSTRLEN));
    printf("\n\tType de protocole transport : ");

    *longueur_trame_restante -= 40; //40 = taille de l'entête IPv6
    int longueur_paquet_restante = ntohs(ip6->ip6_plen);   //nombre d'octets non encore lus dans le paquet IPv6
                                    //(pas forcément le nombre d'octets restant dans la trame, car octets de padding éventuels dans trame ethernet)

    //teste si la longueur du paquet IPv6 est cohérente (ni négative ni plus grande que la longueur de la trame)
    if (longueur_paquet_restante < 0 || longueur_paquet_restante > *longueur_trame_restante){
        printf("Erreur : longueur payload IPv6 incorrecte");
        return;
    }

    switch(ip6->ip6_nxt){
        case IPPROTO_UDP:
            printf("UDP");
            analyse_UDP(packet+14+40, longueur_trame_restante, &longueur_paquet_restante); //14 = taille en-tête ethernet, 40 = taille de l'entête IPv6
            break;
        case IPPROTO_TCP:
            printf("TCP");
            analyse_TCP(packet+14+40, longueur_trame_restante, &longueur_paquet_restante);
            break;
        case IPPROTO_ICMPV6:
            printf("ICMPv6");
            analyse_ICMPv6(packet+14+40, longueur_trame_restante, &longueur_paquet_restante);
            break;
        default:
            printf("(Protocole transport non reconnu)");
            break;
    }


}