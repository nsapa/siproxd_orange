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

#include "salsa20-orange.h"
#include "salsa20-init_state.h"
#include "utils.h"

#include <string.h>






void salsa20_rounds(int* in, int* out)
{
   int i;

   uint32_t x[16];

   for (i = 0; i < 16; i++)
   {
      x[i]  = le32toh(in[i]);
   }

   /* c'est du Salsa20 ! */
   for (i = 0; i < 10; i++)
   {
      /* ronde paire */
      x[4]  ^= ((x[12] + x[0]) >> 25) ^ ((x[12] + x[0]) << 7);
      x[8]  ^= ((x[4] + x[0]) >> 23) ^ ((x[4] + x[0]) << 9);
      x[12] ^= ((x[8] + x[4]) >> 19) ^ ((x[8] + x[4]) << 13);
      x[0]  ^= ((x[8] + x[12]) >> 14) ^ ((x[8] + x[12]) << 18);

      x[9]  ^= ((x[1] + x[5]) >> 25) ^ ((x[1] + x[5]) << 7);
      x[13] ^= ((x[9] + x[5]) >> 23) ^ ((x[9] + x[5]) << 9);
      x[1]  ^= ((x[13] + x[9]) >> 19) ^ ((x[13] + x[9]) << 13);
      x[5]  ^= ((x[13] + x[1]) >> 14) ^ ((x[13] + x[1]) << 18);

      x[14] ^= ((x[10] + x[6]) >> 25) ^ ((x[10] + x[6]) << 7);
      x[2]  ^= ((x[14] + x[10]) >> 23) ^ ((x[14] + x[10]) << 9);
      x[6]  ^= ((x[14] + x[2]) >> 19) ^ ((x[14] + x[2]) << 13);
      x[10] ^= ((x[2] + x[6]) >> 14) ^ ((x[2] + x[6]) << 18);

      x[3]  ^= ((x[15] + x[11]) >> 25) ^ ((x[15] + x[11]) << 7);
      x[7]  ^= ((x[3] + x[15]) >> 23) ^ ((x[3] + x[15]) << 9);
      x[11] ^= ((x[3] + x[7]) >> 19) ^ ((x[3] + x[7]) << 13);
      x[15] ^= ((x[7] + x[11]) >> 14) ^ ((x[7] + x[11]) << 18);

      /* ronde impaire */
      x[1]  ^= ((x[0] + x[3]) >> 25) ^ ((x[0] + x[3]) << 7);
      x[2]  ^= ((x[0] + x[1]) >> 23) ^ ((x[0] + x[1]) << 9);
      x[3]  ^= ((x[1] + x[2]) >> 19) ^ ((x[1] + x[2]) << 13);
      x[0]  ^= ((x[2] + x[3]) >> 14) ^ ((x[2] + x[3]) << 18);

      x[6]  ^= ((x[4] + x[5]) >> 25) ^ ((x[4] + x[5]) << 7);
      x[7]  ^= ((x[6] + x[5]) >> 23) ^ ((x[6] + x[5]) << 9);
      x[4]  ^= ((x[6] + x[7]) >> 19) ^ ((x[6] + x[7]) << 13);
      x[5]  ^= ((x[4] + x[7]) >> 14) ^ ((x[4] + x[7]) << 18);

      x[11] ^= ((x[9] + x[10]) >> 25) ^ ((x[9] + x[10]) << 7);
      x[8]  ^= ((x[10] + x[11]) >> 23) ^ ((x[10] + x[11]) << 9);
      x[9]  ^= ((x[8] + x[11]) >> 19) ^ ((x[8] + x[11]) << 13);
      x[10] ^= ((x[8] + x[9]) >> 14) ^ ((x[8] + x[9]) << 18);

      x[12] ^= ((x[14] + x[15]) >> 25) ^ ((x[14] + x[15]) << 7);
      x[13] ^= ((x[12] + x[15]) >> 23) ^ ((x[12] + x[15]) << 9);
      x[14] ^= ((x[12] + x[13]) >> 19) ^ ((x[12] + x[13]) << 13);
      x[15] ^= ((x[13] + x[14]) >> 14) ^ ((x[13] + x[14]) << 18);
   }

   for (i = 0; i < 16; i++)
   {
      out[i] = htole32(x[i] ^ le32toh(in[i]));
   }
}




/* This function is a misnomer because this isn't quite Salsa20.  Orange uses
 * its own method to initialize the state and doesn't use the official Salsa20
 * implementation's method.  */
void salsa20_enc(unsigned int a1, uint16_t* scratch, uint8_t *token)
{
   int i, j, k, s, t;

   int state[16] = { 0 };
   int buf_temp[16] = { 0 };
   int buf_out[16];


   for (k = 0; k < 9; k++)
   {
      /* Copy initial state */
      for (i = 0; i < 16; i++)
      {
         uint32_t row = htole16(scratch[k * 8]) << 3;
         state[i] = htole32(init_state[row + (i & 7)]);
      }

      /* Compute rounds on state */
      s = 16;
      for (t = 0; t < 4; t++)
      {
         for (; s < 32; s++)
         {
            uint32_t row;

            if (32 * t + s >= 128)
               break;

            salsa20_rounds(state, buf_out);

            row = (le32toh(*(uint32_t*)&scratch[2 * (4 * k + t)]) >> s) & 1;

            for (j = 0; j < 16; j++)
               state[j] = buf_out[8 * row + (j & 7)];

         }

         s = 0;
      }

      for (i = 0; i < 8; i++)
         buf_temp[i] ^= state[i];

   }

   memcpy(buf_temp + 8, buf_temp, 8 * sizeof(uint32_t));

   for (j = 0; j < a1 ; j++)
   {
      buf_temp[0] ^= le32toh(j + 1);

      salsa20_rounds(buf_temp, buf_out);

      for (i = 0; i < 8; i++)
         *((uint32_t*)(token) + (8 * j + i)) ^= buf_out[i];
   }
}






