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
#include "analyse_application.h"

void avance_analyse_bootp (const u_char **option, int *longueur_restante_trame, int *longueur_restante_paquet, u_char nombre_octets){
    int nombre_octets_int = (int) nombre_octets;
    *option += nombre_octets;      //on avance de la longueur de l'option + 2 octets (1 pour le code de l'option, 1 pour la longueur)
    *longueur_restante_trame -= nombre_octets_int;
    *longueur_restante_paquet -= nombre_octets_int;
}

void analyse_bootp(const u_char *packet, int *longueur_restante_trame, int *longueur_restante_paquet){
    printf("\nAnalyse BOOTP : ");
    const struct bootp *bootp;
    bootp = (struct bootp *) (packet);
    printf("\n\tType opération: (%d), ", bootp->bp_op);
    switch(bootp->bp_op){
        case 1:
            printf("Requête");
            break;
        case 2:
            printf("Réponse");
            break;
        default:
            printf("(Type inconnu)");
            break;
    }
    printf("\n\tType de matériel: %d, ", bootp->bp_htype);
    printf("\n\tLongueur adresse matérielle: %d, ", bootp->bp_hlen);
    printf("\n\tGateway hops: %d, ", bootp->bp_hops);
    printf("\n\tTransaction ID: %d, ", bootp->bp_xid);
    printf("\n\tSeconds since boot began: %d, ", bootp->bp_secs);
    printf("\n\tClient IP address: %s, ", inet_ntoa(bootp->bp_ciaddr));
    printf("\n\tYour IP address: %s, ", inet_ntoa(bootp->bp_yiaddr));
    printf("\n\tServer IP address: %s, ", inet_ntoa(bootp->bp_siaddr));
    printf("\n\tGateway IP address: %s, ", inet_ntoa(bootp->bp_giaddr));
    printf("\n\tClient hardware address: %02x:%02x:%02x:%02x:%02x:%02x, ", bootp->bp_chaddr[0], bootp->bp_chaddr[1], bootp->bp_chaddr[2], bootp->bp_chaddr[3], bootp->bp_chaddr[4], bootp->bp_chaddr[5]);
    if (strlen(bootp->bp_sname) > 0) printf("\n\tServer host name: %s, ", bootp->bp_sname); else printf("\n\tServer host name: (non renseigné), ");
    if (strlen(bootp->bp_file) > 0) printf("\n\tBoot file name: %s, ", bootp->bp_file); else printf("\n\tBoot file name: (non renseigné), ");

    *longueur_restante_paquet -= 236; //236 = taille de l'entête BOOTP
    *longueur_restante_trame -= 236; //236 = taille de l'entête BOOTP

    //analyse des options
    printf("\n\tOptions : ");
    const u_char *option = bootp->bp_vend;
    //teste si le magic number DHCP est présent (99, 130, 83, 99) -> 63, 82, 53, 63 en hexadécimal
    if ( *(option) == 99 && *(option+1) == 130 && *(option+2) == 83 && *(option+3) == 99){
        printf("\n\t\tRequête DHCP (magic number : 0x%02x%02x%02x%02x)", *(option), *(option+1), *(option+2), *(option+3));

        //on avance de 4 octets (magic number)
        option += 4;
        *longueur_restante_trame -= 4;
        *longueur_restante_paquet -= 4;

        while (*longueur_restante_paquet > 0 && *option != 255){

            char longueur_option_char = *(option+1);
            int longueur_option = (int) (*(option+1));
            printf("\n\t\t\ttest Code option : %d, longueur option : %d", *option, longueur_option);   //débogage
            printf("\n\t\t\tOption: (%d) ", *option);
            //printf("test : %d %d", longueur_option, *longueur_restante_paquet);   //débogage

            //teste si la longueur de l'option est cohérente pour éviter de lire des données en dehors du paquet (seg fault)
            if (longueur_option+2 > *longueur_restante_paquet){
                printf("\n\t\tErreur : longueur option DHCP incorrecte (arrêt de l'analyse des options)");
                return;
            }


            switch (*option){

                case 1: //Masque de sous-réseau
                    printf("Subnet mask : %d.%d.%d.%d", *(option+2), *(option+3), *(option+4), *(option+5));
                   // on avance de la longueur de l'option + 2 octets (1 pour le code de l'option, 1 pour la longueur)
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, longueur_option_char+2); 
                    break;

                case 3: //Adresse IP routeur
                    printf("Router : %d.%d.%d.%d", *(option+2), *(option+3), *(option+4), *(option+5));
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, longueur_option_char+2);
                    break;

                case 6: //Serveur DNS
                    printf("DNS server : ");
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);

                    int nombre_serveurs_dns = longueur_option/4;
                    for (int i = 1; i<=nombre_serveurs_dns; i++){
                        printf("\n\t\t\t\tDNS server (%d) : %d.%d.%d.%d", i, *(option), *(option+1), *(option+2), *(option+3));
                        //on avance de la longueur de l'option + 2 octets (1 pour le code de l'option, 1 pour la longueur)
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 4);
                    }
                    break;

                case 12:
                    printf("Hostname : ");
                    //on avance de 2 octets (1 pour le code de l'option, 1 pour la longueur)
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);
                    for (int i = 0; i<longueur_option; i++){
                        printf("%c", *option);
                        /*option++;
                        *longueur_restante_trame--;
                        *longueur_restante_paquet--;*/
                       avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                    }
                    break;

                case 15:
                    printf("Domain name : ");
                       avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);                  
                    while (*option != 0){
                        printf("%c", *option);
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                    }
                    //décalage après dernier octet nul (caractère de fin de chaîne)
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                    break;

                case 28: //broadcast address
                    printf("Broadcast address : ");
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);
                    if (longueur_option == 4) { //adresse IP
                        printf("%d.%d.%d.%d", *(option+2), *(option+3), *(option+4), *(option+5));
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 4);
                    }
                    else {  //type non reconnu : affichage simple en hexadecimal
                        for (int i = 0; i<longueur_option; i++){
                            printf("0x%02x ", *option);
                            avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                        }
                    }
                    break;

                case 50: //adresse IP demandée
                    printf("Requested IP address : ");
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);
                    if (longueur_option == 4){ //adresse IP
                        printf("%d.%d.%d.%d", *(option), *(option+1), *(option+2), *(option+3));
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 4);
                    }
                    else{   //type non reconnu : affichage simple en hexadecimal
                        for (int i = 0; i<longueur_option; i++){
                            printf("0x%02x ", *option);
                            avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                        }
                    }
                    break;

                case 51: //lease time
                    printf("Lease time : ");
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);
                    for (int i = 0; i<longueur_option; i++){ //affichage simple en hexadecimal
                        printf("0x%02x ", *option);
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                    }
                    
                    break;

                case 53:
                    printf("Message type : %d", *(option+2));
                    switch(*(option+2)){
                        case 1:
                            printf(" (DHCPDISCOVER)");
                            break;
                        case 2:
                            printf(" (DHCPOFFER)");
                            break;
                        case 3:
                            printf(" (DHCPREQUEST)");
                            break;
                        case 5:
                            printf(" (DHCPACK)");
                            break;
                        case 7:
                            printf(" (DHCPRELEASE)");
                            break;
                        default:
                            printf(" (type non reconnu)");
                            break;
                    }
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 3);
                    break;

                case 54: //serveur identifier
                    printf("Server identifier : ");
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);

                    if (longueur_option == 4){ //adresse IP
                        printf("%d.%d.%d.%d", *(option), *(option+1), *(option+2), *(option+3));
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 4);
                    }
                    else{   //type non reconnu : affichage simple en hexadecimal
                        for (int i = 0; i<longueur_option; i++){
                        printf("0x%02x ", *option);
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                    }
                    }
                    break;

                case 55: // paramètres demandés
                    printf("Paramètres demandés : ");
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);
                    for (int i = 0; i<longueur_option; i++){
                        printf("%d ", *option);
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                    }
                    break;

                case 61: // client identifier
                    printf("Client identifier : ");
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 2);

                    if (*option == 1 && longueur_option == 7){ //adresse ethernet
                        printf("%02x:%02x:%02x:%02x:%02x:%02x (adresse ethernet)", *(option+1), *(option+2), *(option+3), *(option+4), *(option+5), *(option+6));
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 7);
                    }
                    else{   //type non reconnu : affichage simple en hexadecimal
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                        for (int i = 0; i<longueur_option; i++){
                        printf("0x%02x ", *option);
                        /*option++;
                        *longueur_restante_trame--;
                        *longueur_restante_paquet--;*/
                        avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
                    }
                    }
                    break;

                //cas 255 non traité car while (*option != 255) -> on sort de la boucle


                default:    //option non reconnue
                    printf("\n\t\t\tOption non reconnue");
                    /*option += longueur_option_char+2;
                    *longueur_restante_trame -= longueur_option+2;
                    *longueur_restante_paquet -= longueur_option+2;*/
                    avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, longueur_option_char+2);
                    break;
            }
        }
        
        //fin de la liste d'options
        if (*option == 255){
            printf("\n\t\tOption de fin DHCP (255, 0xff)");
            printf("\n\t\tOptions DHCP terminées");
            avance_analyse_bootp(&option, longueur_restante_trame, longueur_restante_paquet, 1);
            return;
        }
        else{
            printf("\n\t\tErreur : option DHCP non terminée par 255");
            return;
        }
    }
    else{
        printf("\n\t\tMagic number DHCP non trouvé");
    }


}

void analyse_http(const u_char *packet);