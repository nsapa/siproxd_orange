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

#include "base64.h"

void base64_decode(const char* data, char* result, size_t result_len)
{
   const char* c;
   int s = 0;
   int t = 0;
   int l, v;

   for (c = data, l = 0; *c && l <= result_len; c++) {
      if ('A' <= *c && *c <= 'Z')
         v = (*c) - 'A';
      else if ('a' <= *c && *c <= 'z')
         v = (*c) - 'a' + 26;
      else if ('0' <= *c && *c <= '9')
         v = (*c) - '0' + 52;
      else if (*c == '+')
         v = 62;
      else if (*c == '/')
         v = 63;
      else 
         v = 0;

      t += 6;
      s |= v;

      if (t >= 8) {
         t -= 8;
         result[l++] = (s >> t) & 0xff;
      }
      
      s <<= 6;

   }
}
