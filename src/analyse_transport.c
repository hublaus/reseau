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
#include "analyse_transport.h"
#include "analyse_application.h"

/*
//A modifier si on veut ajouter des flux TCP
//Choix effectué : taille fixe du tableau de flux TCP pour éviter problèmes de gestion de mémoire (de toute manière en pratique,
//le nombre de flux TCP est limité)
#define NOMBRE_FLUX_TCP_IPV4_MAX 20
#define NOMBRE_FLUX_TCP_IPV6_MAX 20

volatile ipv4_tcp_stream flux_tcp_ipv4[NOMBRE_FLUX_TCP_IPV4_MAX];
volatile ipv6_tcp_stream flux_tcp_ipv6[NOMBRE_FLUX_TCP_IPV6_MAX];
*/

//Cette partie visait à mettre en oeuvre la possibilité de reconstituer un paquet TCP fragmenté
//ainsi qu'à conserver les données de plusieurs flux TCP en simultané
//Finalement, je considère que ce n'est pas nécessaire pour le projet, et que cela complexifie inutilement le code
//Je laisse cependant cet extrait de code en commentaire pour montrer la démarche
//Ainsi, on considère que cette interface ne contient qu'un seul flux TCP à la fois


void analyse_UDP(const u_char *trame_UDP, int *longueur_restante_trame, int *longueur_restante_paquet){
    //test avant cast pour éviter segmentation fault
    if (*longueur_restante_trame < 8){
        printf("Trame Ethernet trop courte pour contenir une entête UDP, paquet erroné");
        return;
    }

    printf("\nAnalyse UDP : ");
    const struct udphdr *udp;
    udp = (struct udphdr *) (trame_UDP); //14 = taille en-tête ethernet, 4*ip->ip_hl = taille de l'entête IP
    printf("\n\tPort source: %d, ", ntohs(udp->uh_sport));
    printf("\n\tPort destination: %d, ", ntohs(udp->uh_dport));
    printf("\n\tLongueur: %d, ", ntohs(udp->uh_ulen));
    printf("\n\tChecksum: %d, ", ntohs(udp->uh_sum));
    printf("\n\tApplication : ");

    *longueur_restante_paquet -= 8; //8 = taille de l'entête UDP
    *longueur_restante_trame -= 8; //8 = taille de l'entête UDP

    switch (ntohs(udp->uh_dport)){ // -> UDP se sert du port de destination pour démultiplexer les données
        case IPPORT_BOOTPS: //port 67, BOOTP Server
            printf("BOOTP (client vers serveur)");
            printf(" test : %d %d", *longueur_restante_trame, *longueur_restante_paquet);
            analyse_bootp(trame_UDP+8, longueur_restante_trame, longueur_restante_paquet); //8 = taille de l'entête UDP
            break;
        case IPPORT_BOOTPC: //port 68, BOOTP Client
            printf("BOOTP (serveur vers client)");
            analyse_bootp(trame_UDP+8, longueur_restante_trame, longueur_restante_paquet); //8 = taille de l'entête UDP
            break;
        case 53: //port 53, DNS
            printf("DNS");
            break;
        default:
            printf("Port non reconnu");
            break;
    }
}


void analyse_TCP(const u_char *trame_TCP, int *longueur_restante_trame, int *longueur_restante_paquet){
    printf("\nAnalyse TCP : ");
    const struct tcphdr *tcp;
    tcp = (struct tcphdr *) (trame_TCP); //40 = taille de l'entête IPv6
    printf("\n\tPort source: %d, ", ntohs(tcp->th_sport));
    printf("\n\tPort destination: %d, ", ntohs(tcp->th_dport));
    printf("\n\tNuméro de séquence: %u, ", ntohl(tcp->th_seq));
    printf("\n\tNuméro d'acquittement: %u, ", ntohl(tcp->th_ack));
    printf("\n\tLongueur entête: %d, ", tcp->th_off);
    printf("\n\tFlags: ");
    if (tcp->th_flags & TH_FIN) printf("FIN ");   //flag FIN, indiquant la fin de la connexion
    if (tcp->th_flags & TH_SYN) printf("SYN ");   //flag SYN, indiquant le début de la connexion
    if (tcp->th_flags & TH_RST) printf("RST ");   //flag RST, indiquant la réinitialisation de la connexion
    if (tcp->th_flags & TH_PUSH) printf("PUSH "); //flag PUSH, indiquant que les données doivent être transmises à l'application
    if (tcp->th_flags & TH_ACK) printf("ACK ");   //flag ACK, indiquant que le numéro d'acquittement est valide
    if (tcp->th_flags & TH_URG) printf("URG ");   //flag URG, indiquant que le pointeur urgent est valide (utilisé pour les données urgentes)
    printf("\n\tWindow: %d, ", ntohs(tcp->th_win));
    printf("\n\tChecksum: %d, ", ntohs(tcp->th_sum));
    printf("\n\tPointeur urgent: %d, ", ntohs(tcp->th_urp));


}


void analyse_ICMP(const u_char *trame_ICMP, int *longueur_restante_trame, int *longueur_restante_paquet){
    printf("\nAnalyse ICMP : ");
    const struct icmphdr *icmp;
    icmp = (struct icmphdr *) (trame_ICMP); //40 = taille de l'entête IPv6
    printf("\n\tType: %d, ", icmp->type);
    printf("\n\tCode: %d, ", icmp->code);
    printf("\n\tChecksum: %d, ", ntohs(icmp->checksum));

    //A compléter
}

void analyse_ICMPv6(const u_char *trame_ICMPv6, int *longueur_restante_trame, int *longueur_restante_paquet){
    printf("\nAnalyse ICMPv6 : ");
    const struct icmp6_hdr *icmp6;
    icmp6 = (struct icmp6_hdr *) (trame_ICMPv6); //40 = taille de l'entête IPv6
    printf("\n\tType: %d, ", icmp6->icmp6_type);
    printf("\n\tCode: %d, ", icmp6->icmp6_code);
    printf("\n\tChecksum: %d, ", ntohs(icmp6->icmp6_cksum));

    //A compléter
}