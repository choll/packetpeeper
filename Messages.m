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

#import <Foundation/NSString.h>
#import <Foundation/NSArchiver.h>
#include "Messages.h"

@implementation MsgQuit

- (void)encodeWithCoder:(NSCoder *)coder
{
	return;
}

- (id)initWithCoder:(NSCoder *)coder
{
	self = [super init];
	return self;
}

@end

@implementation MsgSettings

- (void)encodeWithCoder:(NSCoder *)coder
{
	[coder encodeObject:iface];
	[coder encodeValueOfObjCType:@encode(unsigned int) at:&buflen];
	[coder encodeValueOfObjCType:@encode(struct timeval) at:&timeout];
	[coder encodeValueOfObjCType:@encode(BOOL) at:&promisc];
	[coder encodeValueOfObjCType:@encode(BOOL) at:&immediate];
	[coder encodeObject:filterProgram];
}

- (id)initWithCoder:(NSCoder *)coder
{
	if((self = [super init]) != nil) {
		iface = [[coder decodeObject] retain];
		[coder decodeValueOfObjCType:@encode(unsigned int) at:&buflen];
		[coder decodeValueOfObjCType:@encode(struct timeval) at:&timeout];
		[coder decodeValueOfObjCType:@encode(BOOL) at:&promisc];
		[coder decodeValueOfObjCType:@encode(BOOL) at:&immediate];
		filterProgram = [[coder decodeObject] retain];
	}
	return self;
}

- (id)initWithInterface:(NSString *)ifaceVal bufLength:(unsigned int)buflenVal timeout:(struct timeval *)timeoutVal promiscuous:(BOOL)promiscVal immediate:(BOOL)immediateVal filterProgram:(PPBPFProgram *)aFilterProgram
{
	if((self = [super init]) != nil) {
		if(timeoutVal != NULL) {
			timeout = *timeoutVal;
		} else {
			timeout.tv_sec = 0;
			timeout.tv_usec = 0;
		}
		iface = [ifaceVal retain];
		buflen = buflenVal;
		promisc = promiscVal;
		immediate = immediateVal;
		filterProgram = [aFilterProgram retain];
	}
	return self;
}

- (id)init
{
	return [self initWithInterface:@"" bufLength:0 timeout:NULL promiscuous:NO immediate:YES filterProgram:nil];
}

- (NSString *)interface
{
	return iface;
}

- (struct timeval *)timeout
{
	return &timeout;
}

- (unsigned int)bufLength
{
	return buflen;
}

- (BOOL)promiscuous
{
	return promisc;
}

- (BOOL)immediate
{
	return immediate;
}

- (PPBPFProgram *)filterProgram
{
	return filterProgram;
}

- (void)dealloc
{
	[iface release];
	[filterProgram release];
	[super dealloc];
}

@end
