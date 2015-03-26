/*
 * Copyright (C) 2014 x0r <x0r@x0r.fr>
 *
 * This file is part of siproxd_orange.
 *
 * siproxd_orange is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * siproxd_orange is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warrantry of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with siproxd_orange; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

#ifndef LP_AUTH_H
#define LP_AUTH_H

/* Hack: get around 'enum type' namespace pollution by curl < 7.32.0 */
#define type curl_khtype
#include <curl/curl.h>
#undef type

struct step1_result {
   char* status;
   char* token;
};

struct sip_params {
   char* out_proxy;        /* VoiceProfile/OutboundProxy */
   char* out_proxy_port;   /* VoiceProfile/OutboundProxyPortNumber */
   short local_port;       /* LocalPortNumber */
   short register_delay;   /* RegistrationDelay */
   char* ua_domain;        /* UserAgentDomain */
   char* ndip;             /* NDIP */
   char* impi;             /* IMPI */
   char* sip_uri;          /* URISIP */
   char* auth_data;        /* AuthentData */
   char* ua_string;        /* SiPUserAgent (not a typo) */
   char  ha1[33];          /* HA1 for response to challenge, computed later */
};


struct step1_result* auth_step1(CURL* curl, char* user, char* password);
int auth_step2(CURL* curl, struct step1_result* s1r, struct sip_params** p_s2r);


void dump_sip_params(struct sip_params* p);

void step1_result_free(struct step1_result* s1r);
void sip_params_free(struct sip_params* s2r);

void compute_digest_ha1(struct sip_params* s2r);

#endif
