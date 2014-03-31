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

#include <string.h>
#include <stdlib.h>
#import <Foundation/NSString.h>
#import <Foundation/NSCoder.h>
#include "ErrorStack.h"

@implementation ErrorStack

+ (ErrorStack *)sharedErrorStack
{
	static ErrorStack *shared;

	if(shared == nil)
		shared = [[ErrorStack alloc] init];

	return shared;
}

- (id)init
{
	if((self = [super init]) != nil) {
		if((elems = malloc(sizeof(*elems) * ERRORSTACK_SZ)) == NULL) {
			[super dealloc];
			return nil;
		}
		size = ERRORSTACK_SZ;
		index = 0;
	}
	return self;
}

- (void)pushError:(NSString *)description
				  lookup:(Class)lookup
				  code:(unsigned int)code
				  severity:(unsigned int)severity
{
	/* allocate more memory if needed */
	if(index == size) {
		void *temp;
		if((temp = realloc(elems, sizeof(*elems) * (size + ERRORSTACK_SZ))) == NULL) {
			/* if we cant allocate more memory, but have other entires, reset ourself
			   and use that memory. Otherwise bail out silently */
			if(index)
				[self reset];
			else
				return;
		} else {
			size += ERRORSTACK_SZ;
			elems = temp;
		}
	}

	elems[index].description = [description retain];
	elems[index].lookup = lookup;
	elems[index].code = code;
	elems[index].severity = severity;
	++index;
}

- (void)pop
{
	if(index)
		[elems[--index].description release];
}

- (NSString *)lookupString
{
	if(index && elems[index - 1].lookup != Nil)
		return [elems[index - 1].lookup stringForErrorCode:elems[index - 1].code];
	else
		return nil;
}

- (NSString *)descriptionString
{
	if(index)
		return elems[index - 1].description;
	else
		return nil;
}

- (Class)lookup
{
	if(index)
		return elems[index - 1].lookup;
	else
		return 0;
}

- (NSString *)domain
{
	if(index)
		return [elems[index - 1].lookup errorDomain];
	else
		return nil;
}

- (unsigned int)code
{
	if(index)
		return elems[index - 1].code;
	else
		return 0;
}

- (unsigned int)severity
{
	if(index)
		return elems[index - 1].severity;
	else
		return 0;
}

- (void)reset
{
	while([self size])
		[self pop];
}

- (unsigned int)size
{
	return index;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
	int i;

	[coder encodeValueOfObjCType:@encode(unsigned int) at:&index];
	[coder encodeValueOfObjCType:@encode(unsigned int) at:&size];
	for(i = 0; i < index; ++i) {
		[coder encodeObject:elems[i].description];
		[coder encodeValueOfObjCType:@encode(Class) at:&elems[i].lookup];
		[coder encodeValueOfObjCType:@encode(unsigned int) at:&elems[i].code];
		[coder encodeValueOfObjCType:@encode(unsigned int) at:&elems[i].severity];
	}
}

- (id)initWithCoder:(NSCoder *)coder
{
	if((self = [super init]) != nil) {
		int i;

		[coder decodeValueOfObjCType:@encode(unsigned int) at:&index];
		[coder decodeValueOfObjCType:@encode(unsigned int) at:&size];
		if((elems = malloc(sizeof(*elems) * size)) == NULL) {
			[super dealloc];
			return nil;
		}
		for(i = 0; i < index; ++i) {
			elems[i].description = [[coder decodeObject] retain];
			[coder decodeValueOfObjCType:@encode(Class) at:&elems[i].lookup];
			[coder decodeValueOfObjCType:@encode(unsigned int) at:&elems[i].code];
			[coder decodeValueOfObjCType:@encode(unsigned int) at:&elems[i].severity];
		}
	}
	return self;
}

- (void)dealloc
{
	[self reset];
	free(elems);
	[super dealloc];
}

@end

@implementation PosixError

+ (NSString *)stringForErrorCode:(unsigned int)code
{
	return [NSString stringWithUTF8String:strerror(code)];
}

+ (NSString *)errorDomain
{
	return @"POSIX";
}

@end

