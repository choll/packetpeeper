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

#include <limits.h>
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>
#import <Foundation/NSString.h>
#import <Foundation/NSValue.h>
#import <Foundation/NSDecimalNumber.h>
#include "PPDataQuantityFormatter.h"

#define	BYTES_GB	(1024 * 1024 * 1024)
#define BYTES_MB	(1024 * 1024)
#define BYTES_KB	1024

#define ULLONG_MAX_GB	(ULLONG_MAX / BYTES_GB)
#define ULLONG_MAX_MB	(ULLONG_MAX / BYTES_MB)
#define ULLONG_MAX_KB	(ULLONG_MAX / BYTES_KB)

@implementation PPDataQuantityFormatter

- (BOOL)getObjectValue:(id *)anObject forString:(NSString *)aString errorDescription:(NSString **)errorString
{
	unsigned long long bytes;
	const char *str;
	char *endptr;

	if([aString length] < 1) {
		*anObject = [NSNumber numberWithUnsignedLongLong:0];
		return YES;
	}

	str = [aString UTF8String];

	if((bytes = strtoull(str, &endptr, 10)) == ULLONG_MAX || endptr == str)
		return NO;

	while(isspace(*endptr))
		++endptr;

	if(bytes != 0) {
		if(strcasecmp(endptr, "GB") == 0 || strcasecmp(endptr, "gigabytes") == 0) {
			if(bytes > ULLONG_MAX_GB)
				bytes = ULLONG_MAX;
			else
				bytes *= BYTES_GB;
		} else if(strcasecmp(endptr, "MB") == 0 || strcasecmp(endptr, "M") == 0 || strcasecmp(endptr, "megabytes") == 0) {
			if(bytes > ULLONG_MAX_MB)
				bytes = ULLONG_MAX;
			else
				bytes *= BYTES_MB;
		} else if(strcasecmp(endptr, "KB") == 0 || strcasecmp(endptr, "K") == 0 || strcasecmp(endptr, "kilobytes") == 0) {
			if(bytes > ULLONG_MAX_KB)
				bytes = ULLONG_MAX;
			else
				bytes *= BYTES_KB;
		}
		/* no units specified, taken as bytes */
	}

	*anObject = [NSNumber numberWithUnsignedLongLong:bytes];

	return YES;
}

- (NSString *)stringForObjectValue:(id)anObject
{
	if([anObject isKindOfClass:[NSNumber class]])
		return data_quantity_str([anObject unsignedLongLongValue]);

	return nil;
}

@end

NSString *data_quantity_str(unsigned long long nbytes)
{
	if(nbytes >= BYTES_GB)
		return [NSString stringWithFormat:@"%g GB", nbytes / (double)BYTES_GB];
	else if(nbytes >= BYTES_MB)
		return [NSString stringWithFormat:@"%g MB", nbytes / (double)BYTES_MB];
	else if(nbytes >= BYTES_KB)
		return [NSString stringWithFormat:@"%g KB", nbytes / (double)BYTES_KB];

	return [NSString stringWithFormat:@"%llu B", nbytes];
}
