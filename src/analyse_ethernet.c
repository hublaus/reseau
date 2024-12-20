#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "bootp.h"
#include "args_ligne_commande.h"
#include "analyse_ethernet.h"
#include "analyse_reseau.h"

void analyse_ethernet(const u_char *packet, int *longueur_restante_trame){
    printf("\nAnalyse Ethernet : nombre d'octets dans la trame : %d", *longueur_restante_trame);

    //test avant cast pour éviter segmentation fault
    if (*longueur_restante_trame < 14){
        printf("\nTrame Ethernet trop courte pour contenir une entête Ethernet, paquet erroné");
        return;
    }
    
    const struct ether_header *ethernet;
    ethernet = (struct ether_header *) (packet);

    printf("\n\tAdresse MAC destination: %02x:%02x:%02x:%02x:%02x:%02x, ", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
    printf("\n\tAdresse MAC source: %02x:%02x:%02x:%02x:%02x:%02x, ", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);

    *longueur_restante_trame -= 14; //14 = taille fixe d'une entête ethernet (6 octets pour adresse MAC source, 6 octets pour adresse MAC destination, 2 octets pour type)

//la fonction ntohs permet de changer l'ordre des octets (poids fort et faible)
    if ( (ntohs(ethernet->ether_type)) == 0x0806){ //ARP
        printf("Type de protocole réseau : ARP");

        //test avant cast pour éviter segmentation fault
        if (*longueur_restante_trame < 28){
            printf("Reste trame trop court pour contenir une requête ARP, paquet erroné");
            return;
        }

        const struct ether_arp *arp;
        arp = (struct ether_arp *) (packet + 14);   //14 = taille de l'entête ethernet (6 octets pour adresse MAC source, 6 octets pour adresse MAC destination, 2 octets pour type)
        printf("\nType de matériel: %d ", ntohs(arp->arp_hrd));
        if (ntohs(arp->arp_hrd) == 1) printf("(Ethernet)");
        printf(", ");

        printf("Type de protocole: 0x%04x, ", ntohs(arp->arp_pro));
        switch (ntohs(arp->arp_pro)){
            case 0x0800:
                printf("(IP)");
                break;
            case 0x0806:
                printf("(ARP)");
                break;
            default:
                break;
        }
        printf("Longueur adresse matérielle: %d, ", arp->arp_hln);
        printf("Longueur adresse protocole: %d, ", arp->arp_pln);
        printf("Opération: %d, ", ntohs(arp->arp_op));
        printf("Adresse MAC source: %02x:%02x:%02x:%02x:%02x:%02x, ", arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
        printf("Adresse IP source: %d.%d.%d.%d, ", arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
        printf("Adresse MAC destination: %02x:%02x:%02x:%02x:%02x:%02x, ", arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2], arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
        printf("Adresse IP destination: %d.%d.%d.%d, ", arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);

        *longueur_restante_trame -= 28; //28 = taille d'une requête ARP (entête + 2 adresses MAC + 2 adresses IP)
    }

    else if ( (ntohs(ethernet->ether_type)) == 0x0800){ //IPv4
        printf("\n\tType de protocole réseau : IPv4");
        //printf("test : %d", *longueur_restante_trame);
        analyse_ipv4(packet, longueur_restante_trame); //14 = taille en-tête ethernet
    }

    else if ( (ntohs(ethernet->ether_type)) == 0x86dd){ //IPv6
        printf("\n\tType de protocole réseau : IPv6");
        analyse_ipv6(packet, longueur_restante_trame);
    }

    else {
        printf("Type de protocole réseau non traité ou non reconnu (0x%04x, ni IP ni ARP)", ntohs(ethernet->ether_type));
    }

    //affichage octets de padding
    /*if (*longueur_restante_trame > 0){
        printf("\n\tOctets de padding : ");
        for (int i = 0; i < (*longueur_restante_trame); i++){
            printf("%02x ", packet[14+(*longueur_restante_trame)+i]);
        }
    }*/
   printf("\nNombre d'octets restants dans la trame : %d (octets de padding ou protocole non reconnu)", *longueur_restante_trame);

}