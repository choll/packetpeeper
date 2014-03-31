/*
 * Packet Peeper
 * Copyright 2006, 2007, 2008, 2014 Chris E. Holloway
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include <machine/endian.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdio.h>
#include "in_cksum.h"

unsigned int in_cksum_partial(const void *data, unsigned int nbytes, unsigned int sum)
{
	const uint16_t *p;

	p = data;

	while(nbytes > 1) {
		sum += *p++;
		nbytes -= 2;
	}

	if(nbytes > 0) {
		/* add leftover byte with zero pad byte */
#if (BYTE_ORDER == BIG_ENDIAN)
		sum += *(uint8_t *)p << 8;
#elif (BYTE_ORDER == LITTLE_ENDIAN)
		sum += *(uint8_t *)p;
#else
#error "Unknown byte order"
#endif
	}

	return sum;
}

unsigned long in_cksum_fold(unsigned long sum)
{
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += sum >> 16;
	return (~sum & 0xFFFF);
}

