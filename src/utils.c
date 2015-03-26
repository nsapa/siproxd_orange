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

#include <ctype.h>
#include <stdio.h>

#include "utils.h"

#ifndef HAVE_HTOLE32
/* Supply replacement for htole32 and le32toh for older glibcs */

uint32_t byte_swap_32(uint32_t i)
{
   uint32_t result;
   result = (i & 0x000000ff) << 24
          | (i & 0x0000ff00) << 8
          | (i & 0x00ff0000) >> 8
          | (i & 0xff000000) >> 24;
   return result;
}

#endif

#ifndef HAVE_HTOLE16

/* Supply replacement for htole16 and le16toh for older glibcs */

uint16_t byte_swap_16(uint16_t i)
{
   uint16_t result;
   result = (i & 0x00ff) << 8
          | (i & 0xff00) >> 8;
   return result;
}


#endif


void dump_hex(void* ptr, size_t size) {
   int i;

   for (i = 0; i < size; i++) {
      if (i % 16 == 0) 
         printf("%8x | ", i);

      printf("%02hhx ", (int)(((char*)(ptr))[i]));
      if (i % 16 == 7)
         printf(" ");
      if (i % 16 == 15)
         printf("\n");
   }
   if (i % 16 != 15)
      printf("\n");

}




size_t urlencode(char* dest, const char* src)
{
   char *d;
   int i;
   for (i = 0, d = dest; src[i]; i++) {
      if (isalnum(src[i]) || src[i] == '.' || src[i] == '-') {
         if (dest != NULL)
            *d = src[i];
         d++;
      }
      else {
         if (dest != NULL)
            sprintf(d, "%%%02X", src[i]);
         d += 3;
      }
   }

   if (dest != NULL)
      *d = 0;

   return d - dest;
}

