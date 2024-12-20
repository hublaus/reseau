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
//#include <arpa/inet.h>
//#include <netinet/if_ether.h>

volatile long int nb_paquets = 0;

void callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("\n\nPaquet numéro %ld", ++nb_paquets);
    int longueur_restante_trame = pkthdr->len;

    analyse_ethernet(packet, &longueur_restante_trame);

}

void capture_live(options *opt){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs;
    pcap_if_t *dev;

    if(pcap_findalldevs(&all_devs, errbuf) == -1){
        fprintf(stderr, "error finding devices");
        exit(1);
    }

    //device = all_devs->name; // premier device
    //or loop through all_devs to find the one you want

    if (all_devs == NULL) {
        printf("Error finding devices: %s\n", errbuf);
        exit(1);
    }
    pcap_findalldevs(&all_devs, errbuf);

    //find device named opt->interface
    int trouve = 0;
    for (dev = all_devs; dev != NULL; dev = dev->next) {
        if (strcmp(dev->name, opt->interface) == 0) {
            trouve = 1;
            break;
        }
    }
    if (!trouve) {
        fprintf(stderr, "Couldn't find device %s\n", opt->interface);
        exit(2);
    }

    printf("Capture en cours sur l'interface %s", opt->interface);

    handle = pcap_open_live(opt->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", opt->interface, errbuf);
        exit(2);
    }

    pcap_loop(handle, -1, callback, NULL);

    pcap_close(handle);
    pcap_freealldevs(all_devs);

    return;
}

void capture_offline(options *opt){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(opt->fichier_entree, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open file %s: %s\n", opt->fichier_entree, errbuf);
        exit(2);
    }

    printf("Analyse des paquets depuis le fichier %s", opt->fichier_entree);

    pcap_loop(handle, -1, callback, NULL);

    pcap_close(handle);

    return;
}


int main(int argc, char **argv) {

    options opt;  //structure contenant les options de l'utilisateur (voir args_ligne_commande.h)
    traitement_arguments_ligne_de_commande(argc, argv, &opt);

    if (opt.interface != NULL) capture_live(&opt);

    else if (opt.fichier_entree != NULL) capture_offline(&opt);

    return 0;
}