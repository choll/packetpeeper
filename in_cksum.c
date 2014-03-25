/*
 * Packet Peeper
 * Copyright 2006, 2007, Chris E. Holloway
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

#if defined(__ppc__)
static int altivec_enabled(void);
#elif defined(__i386__)
#if 0
static int sse3_enabled(void);
#endif
#endif

unsigned int (*in_cksum_partial)(const void *data, unsigned int nbytes, unsigned int sum) = csum_partial_check;

unsigned int slow_csum_partial(const void *data, unsigned int nbytes, unsigned int sum)
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

unsigned int csum_partial_check(const void *data, unsigned int nbytes, unsigned int sum)
{
	in_cksum_partial = slow_csum_partial;

#if defined(__ppc__)
	if(altivec_enabled()) {
		printf("Using AltiVec Internet checksum routine\n");
		in_cksum_partial = vec_csum_partial;
	}
#elif defined(__i386__)
#if 0
	/* XXX disabled, crash reported at label_41, no hardware available to debug */
	if(sse3_enabled()) {
		printf("Using SSE Internet checksum routine\n");
		in_cksum_partial = sse_csum_partial;
	}
#endif
#endif

	return in_cksum_partial(data, nbytes, sum);
}

unsigned long in_cksum_fold(unsigned long sum)
{
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += sum >> 16;
	return (~sum & 0xFFFF);
}

#if defined(__ppc__)
static int altivec_enabled(void)
{
	int enabled;
	size_t len;

	len = sizeof(enabled);

	if(sysctlbyname("hw.optional.altivec", &enabled, &len, NULL, 0) == 0)
		return enabled;

	return 0;
}
#elif defined(__i386__)
#if 0
static int sse3_enabled(void)
{
	int enabled;
	size_t len;

	len = sizeof(enabled);

	if(sysctlbyname("hw.optional.sse3", &enabled, &len, NULL, 0) == 0)
		return enabled;

	return 0;
}
#endif
#endif
