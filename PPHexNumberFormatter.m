/*
 * Packet Peeper
 * Copyright 2008 Chris E. Holloway
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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#import <Foundation/NSString.h>
#import <Foundation/NSValue.h>
#import <Foundation/NSDecimalNumber.h>
#include "PPHexNumberFormatter.h"

@implementation PPHexNumberFormatter

- (BOOL)getObjectValue:(id *)anObject forString:(NSString *)aString errorDescription:(NSString **)errorString
{
	unsigned long value;
	const char *str;
	char *endptr;

	if([aString length] < 1) {
		*anObject = [NSNumber numberWithUnsignedLong:0];
		return YES;
	}

	str = [aString UTF8String];

	errno = 0;

	value = strtoul(str, &endptr, 16);

	if(value != ULONG_MAX && (errno == ERANGE || endptr == str || *endptr != '\0'))
		return NO;

	*anObject = [NSNumber numberWithUnsignedLong:value];

	return YES;
}

- (NSString *)stringForObjectValue:(id)anObject
{
	if([anObject isKindOfClass:[NSNumber class]]) {
		unsigned long value;

		value = [anObject unsignedLongValue];

		return [NSString stringWithFormat:@"0x%.8lX", value];
	}

	return nil;
}

@end
