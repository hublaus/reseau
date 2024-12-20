#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "args_ligne_commande.h"

void traitement_arguments_ligne_de_commande(int argc, char **argv , options* opt){
    int c;
    opt->verbosite = 1; //option CONCIS par défaut
    opt->interface = NULL;
    opt->fichier_entree = NULL;

    while ((c = getopt (argc, argv, "n:i:o:v")) != -1){
        switch (c){
            case 'v':   //niveau de verbosité (1 pour CONCIS, 2 pour SYNTHETIQUE, 3 POUR complet)
                opt->verbosite = atoi(optarg);
                if (opt->verbosite > 3 || opt->verbosite < 1){
                    fprintf(stderr, "Le niveau de verbosité doit être compris entre 1 et 3\n");
                    exit(1);
                }
                break;
            case 'i':   //interface entrée
                opt->interface = optarg;
                break;
            case 'o':   //fichier d'entrée pour analyse offline
                opt->fichier_entree = optarg;
                break;

        }
    
    }
    if (opt->interface == NULL && opt->fichier_entree == NULL){
        fprintf(stderr, "Il faut une dource d'entrée (option -i 'nom' pour interface, option -o 'nom_fichier' pour analyse offline à partir de fichier d'entrée).\n");
        exit(1);
    }

}