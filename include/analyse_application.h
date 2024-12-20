#pragma once

void analyse_bootp(const u_char *packet, int *longueur_restante_trame, int *longueur_restante_paquet);
void analyse_http(const u_char *packet);