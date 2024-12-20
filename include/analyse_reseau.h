#pragma once

void analyse_ipv4(const u_char *packet, int *longueur_restante_trame);
void analyse_ipv6(const u_char *packet, int *longueur_restante_trame);