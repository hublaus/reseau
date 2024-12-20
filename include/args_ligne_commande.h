#pragma once

/**
* @brief structure stockant les options de la ligne de commande pour l'action bin/fichier_binaire
*/

typedef enum verbosite{
    CONCIS = 1,
    SYNTHETIQUE = 2,
    COMPLET = 3,

} verbosite;

typedef struct options{
    char *interface;
    char *fichier_entree;   //pour analyse offline
    verbosite verbosite;
    } options;

/**
* @brief traite les arguments de la ligne de commande pour l'action bin/fichier_binaire
* @param argc nombre d'arguments de la ligne de commande
* @param argv tableau contenant les arguments de la ligne de commande
* @param opt pointeur sur la structure options dans laquelle seront stockées les options de l'utilisateur
*/
void traitement_arguments_ligne_de_commande(int argc, char **argv, options *opt);