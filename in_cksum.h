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

#ifndef __IN_CKSUM_H__
#define __IN_CKSUM_H__

extern unsigned int (*in_cksum_partial)(const void *data, unsigned int nbytes, unsigned int sum);

unsigned int slow_csum_partial(const void *data, unsigned int nbytes, unsigned int sum);
unsigned int csum_partial_check(const void *data, unsigned int nbytes, unsigned int sum);

/*
	XXX seems that the SSE function produces a big-endian result?
*/

#if defined(__ppc__)
unsigned int vec_csum_partial(const void *data, unsigned int nbytes, unsigned int sum);
#elif defined(__i386__)
#if 0
unsigned int sse_csum_partial(const void *data, unsigned int nbytes, unsigned int sum);
#endif
#endif

unsigned long in_cksum_fold(unsigned long sum);

#endif
