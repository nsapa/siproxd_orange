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

#ifndef LP_MD5_H
#define LP_MD5_C

#include "config.h"


/* the following two functions are taken from siproxd code, but modified to
 * comply better with RFC2617 */

typedef unsigned char HASH[16];
typedef unsigned char HASHHEX[33];

void CvtHex(HASH Bin, HASHHEX Hex);

void compute_digest_response(
         unsigned char HA1[33],         /* H(A1) */
         char * pszNonce,     /* nonce from server */
         char * pszNonceCount,  /* 8 hex digits */
         char * pszCNonce,    /* client nonce */
         char * pszQop,       /* qop-value: "", "auth", "auth-int" */
         char * pszMethod,    /* method from the request */
         char * pszDigestUri, /* requested URL */
         unsigned char HEntity[33],     /* H(entity body) if qop="auth-int" */
         unsigned char Response[33]    /* request-digest or response-digest */
         );


#endif
