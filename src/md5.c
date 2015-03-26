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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <osipparser2/osip_md5.h>

#include "md5.h"




void CvtHex(HASH Bin, HASHHEX Hex)
{
  unsigned short i;
  unsigned char j;
  
  for (i = 0; i < 16; i++) {
    j = (Bin[i] >> 4) & 0xf;
    if (j <= 9)
      Hex[i*2] = (j + '0');
    else
      Hex[i*2] = (j + 'a' - 10);
    j = Bin[i] & 0xf;
    if (j <= 9)
      Hex[i*2+1] = (j + '0');
    else
      Hex[i*2+1] = (j + 'a' - 10);
  };
  Hex[32] = '\0';
}


/* calculate request-digest/response-digest as per HTTP Digest spec */
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
         )
{
   osip_MD5_CTX Md5Ctx;
   HASH HA2;
   HASH RespHash;
   HASHHEX HA2Hex;
   
   /* calculate H(A2) */
   osip_MD5Init(&Md5Ctx);
   if (pszMethod)    osip_MD5Update(&Md5Ctx, (unsigned char*)pszMethod,
                                    strlen(pszMethod));
   osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);
   if (pszDigestUri) osip_MD5Update(&Md5Ctx, (unsigned char*)pszDigestUri,
                                    strlen(pszDigestUri));
   
   if (pszQop!=NULL && !strcmp(pszQop, "auth-int")) {
       osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);
       osip_MD5Update(&Md5Ctx, HEntity, 32);
       osip_MD5Final(HA2, &Md5Ctx);
       CvtHex(HA2, HA2Hex);
       goto auth_withqop;
   };
   
   /* auth_withoutqop: */
   osip_MD5Final(HA2, &Md5Ctx);
   CvtHex(HA2, HA2Hex);
   
   if (pszQop!=NULL) {
       goto auth_withqop;
   }
   
   /* calculate response */
   osip_MD5Init(&Md5Ctx);
   osip_MD5Update(&Md5Ctx, HA1, 32);
   osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);
   if (pszNonce)    osip_MD5Update(&Md5Ctx, (unsigned char*)pszNonce, strlen(pszNonce));
   osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);
   
   goto end;

auth_withqop:


  /* calculate response */
  osip_MD5Init(&Md5Ctx);
  osip_MD5Update(&Md5Ctx, HA1, 32);
  osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);
  if (pszNonce)    osip_MD5Update(&Md5Ctx, (unsigned char*)pszNonce, strlen(pszNonce));
  osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);
  if (pszNonceCount)osip_MD5Update(&Md5Ctx, (unsigned char*)pszNonceCount, strlen(pszNonceCount));
  osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);
  if (pszCNonce)   osip_MD5Update(&Md5Ctx, (unsigned char*)pszCNonce, strlen(pszCNonce));
  osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);
  if (pszQop)      osip_MD5Update(&Md5Ctx, (unsigned char*)pszQop, strlen(pszQop));
  osip_MD5Update(&Md5Ctx, (unsigned char*)":", 1);

end:
  osip_MD5Update(&Md5Ctx, HA2Hex, 32);
  osip_MD5Final(RespHash, &Md5Ctx);
  CvtHex(RespHash, Response);
}



