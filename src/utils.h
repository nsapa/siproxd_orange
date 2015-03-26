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

#ifndef LP_UTILS_H
#define LP_UTILS_H

#include "config.h"

#include <stdlib.h>
#include <stdint.h>



#ifdef HAVE_ENDIAN_H
  #include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
  #include <sys/endian.h>
#endif
#ifdef __OpenBSD__
   #include <sys/types.h>
   #define le32toh letoh32
   #define le16toh letoh16
#endif


#ifndef HAVE_HTOLE32
/* Declare replacement for htole32 and le32toh for older glibcs */
uint32_t byte_swap_32(uint32_t i);
/* Declare replacement for htole16 and le16toh for older glibcs */
uint16_t byte_swap_16(uint16_t i);

#ifdef WORDS_BIGENDIAN
#define htole32(x) byte_swap_32(x)
#define le32toh(x) byte_swap_32(x)
#define htole16(x) byte_swap_16(x)
#define le16toh(x) byte_swap_16(x)
#endif
#ifdef WORDS_LITTLEENDIAN
#define htole32(x) (x)
#define le32toh(x) (x)
#define htole16(x) (x)
#define le16toh(x) (x)
#endif

#endif


#endif

void dump_hex(void* ptr, size_t size);
size_t urlencode(char* dest, const char* src);

