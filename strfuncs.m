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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <machine/endian.h>
#import <Foundation/NSString.h>
#include "strfuncs.h"

/* functions are always expected to return a string, so on error return an empty string */

NSString *binstr(const void *data, unsigned int bits)
{
	NSMutableString *ret;
	unsigned int i;

	if((ret = [NSMutableString stringWithCapacity:bits]) == nil || bits == 0)
		return @"";

	for(i = 0; i < bits; ++i)
#if (BYTE_ORDER == BIG_ENDIAN)
		[ret appendFormat:@"%d", ((((unsigned char *)data)[i / 8] >> (7 - (i % 8))) & 0x1)];
#elif (BYTE_ORDER == LITTLE_ENDIAN)
		[ret appendFormat:@"%d", ((((unsigned char *)data)[((bits - 1) - i) / 8] >> (7 - (i % 8))) & 0x1)];
#else
#error "Unknown byte order"
#endif

	return ret;
}

NSString *hexstr(const void *data, size_t size)
{
	NSMutableString *ret;
	unsigned int i;

	if((ret = [NSMutableString stringWithCapacity:(size * 2) + 2]) == nil)
		return @"";

	[ret appendString:@"0x"];

	for(i = 0; i < size; ++i)
		[ret appendFormat:@"%.2x", ((unsigned char *)data)[i]];

	return ret;
}

NSString *etherstr(const void *data, size_t size)
{
	NSMutableString *ret;
	unsigned int i;

	if((ret = [NSMutableString stringWithCapacity:(size * 3) - 1]) == nil)
		return @"";

	for(i = 0; i < size; ++i)
		[ret appendFormat:@"%s%.2x", (i) ? ":" : "", ((unsigned char *)data)[i]];

	return ret;
}

NSString *ipaddrstr(const void *data, size_t size)
{
	char buf[INET6_ADDRSTRLEN];	/* larger than INET_ADDRSTRLEN */
	int af;

	if(size == sizeof(struct in_addr))
		af = AF_INET;
	else if(size == sizeof(struct in6_addr))
		af = AF_INET6;
	else {
		/* EAFNOSUPPORT */
		return @"";
	}

	if(inet_ntop(af, data, buf, sizeof(buf)) == NULL) {
		/* errno */
		return @"";
	}

	return [NSString stringWithUTF8String:buf];
}
