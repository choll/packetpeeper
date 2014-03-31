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
#include <stdlib.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#import <Foundation/NSDate.h>
#include "bpf_filter.h"
#include "PPDecoderPlugin.h"
#include "PPPluginManager.h"
#include "PPPluginWrapper.h"
#include "Decode.h"
#include "ColumnIdentifier.h"
#include "OutlineViewItem.h"
#include "pkt_compare.h"
#include "DateFormat.h"
#include "PPBPFProgram.h"
#include "PacketPeeper.h"
#include "Packet.h"
#include "PPPacketUIAdditons.h"

static NSString *names[][2] = {{@"Packet number", @"#"},
							   {@"Date received", @"Date received"},
							   {@"Protocols", @"Protocols"},
							   {@"Information", @"Information"},
							   {@"Captured Length", @"Captured Length"},
							   {@"Actual Length", @"Actual Length"}};

@implementation Packet (PacketUIAdditons)

- (void)processPlugins
{
	id <PPDecoderPlugin> plugin;
	id <Decode, Describe> decoder;
	NSData *pluginData;
	PPPluginWrapper *pluginWrapper;
	void *ptr;
	unsigned int i;
	size_t nbytes;
	size_t front;
	size_t rear;

	if(processedPlugins)
		return;

	processedPlugins = YES;
	decoder = nil;
	front = 0;
	rear = 0;

	for(i = 0; i < [decoders count]; ++i) {
		decoder = [decoders objectAtIndex:i];
		front += [decoder frontSize];
		rear += [decoder rearSize];
	}

	if((plugin = [[PPPluginManager sharedPluginManager] pluginDecoderForDecoder:decoder]) == nil)
		return;

	if(front + rear >= [data length])
		return;

	ptr = (uint8_t *)[data bytes] + front;
	nbytes = [data length] - (front + rear);

	pluginData = [[NSData alloc] initWithBytesNoCopy:ptr length:nbytes freeWhenDone:NO];

	if(![plugin isValidData:pluginData]) {
		[pluginData release];
		return;
	}

	pluginWrapper = [[PPPluginWrapper alloc] initWithData:pluginData plugin:plugin];
	[decoders addObject:pluginWrapper];
	[pluginData release];
	[pluginWrapper release];
}

/* Protocol short names in rev. order, (not including link-layer) eg @"UDP, IPv4" */
- (NSString *)protocols
{
	NSMutableString *ret;
	unsigned int n;

	[self processPlugins];

	n = [decoders count];

	if(n < 1)
		return nil;

	ret = [[NSMutableString alloc] init];

	if(n == 1)
		[ret appendString:[[[decoders objectAtIndex:0] class] shortName]];

	while(n-- > 1) {

		if(n == [decoders count] - 1 && [[decoders objectAtIndex:n] isMemberOfClass:[PPPluginWrapper class]])
			[ret appendString:[[decoders objectAtIndex:n] shortName]];
		else
			[ret appendString:[[[decoders objectAtIndex:n] class] shortName]];

		if(n != 1)
			[ret appendString:@", "];
	}

	return [ret autorelease];
}

/* Show the last information string */
- (NSString *)info
{
	NSString *ret;
	unsigned int n;

	[self processPlugins];

	n = [decoders count] - 1;

	do {
		if((ret = [[decoders objectAtIndex:n] info]) != nil)
			return ret;
	} while(n--);

	return nil;
}

- (NSComparisonResult)compare:(Packet *)packet withColumn:(ColumnIdentifier *)column
{
	id decoder_a;
	id decoder_b;

	if(column == nil)
		return val_compare(number, (packet)->number);

	if([column decoder] == [self class])
		return [self compareWith:packet atIndex:[column index]];

	decoder_a = nil;
	decoder_b = nil;

	if([column decoder] != Nil) {
		decoder_a = [self decoderForClass:[column decoder]];
		decoder_b = [packet decoderForClass:[column decoder]];
	} else if([column plugin] != nil) {
		[self processPlugins];
		decoder_a = [self decoderForPlugin:[column plugin]];
		decoder_b = [packet decoderForPlugin:[column plugin]];
	}

	if(decoder_a == nil && decoder_b == nil)
		return NSOrderedSame;

	if(decoder_a == nil && decoder_b != nil)
		return NSOrderedAscending;

	if(decoder_a != nil && decoder_b == nil)
		return NSOrderedDescending;

	return [decoder_a compareWith:decoder_b atIndex:[column index]];
}

/* OutlineViewItem protocol methods */

- (BOOL)expandable
{
	return YES;
}

- (unsigned int)numberOfChildren
{
	[self processPlugins];
	return ([decoders count] + 3);
}

- (id)childAtIndex:(int)fieldIndex
{
	OutlineViewItem *ret;
	NSString *str;

	switch(fieldIndex) {
		case 0:
			ret = [[OutlineViewItem alloc] init];
			[ret addObject:@"Date received"];
			[ret addObject:[date descriptionWithFormat:OUTLINEVIEW_DATE_FORMAT]];
			return [ret autorelease];
			/* NOTREACHED */

		case 1:
			ret = [[OutlineViewItem alloc] init];
			str = [[NSString alloc] initWithFormat:@"%u Byte(s)", actualLength];
			[ret addObject:@"Packet length"];
			[ret addObject:str];
			[str release];
			return [ret autorelease];
			/* NOTREACHED */

		case 2:
			ret = [[OutlineViewItem alloc] init];
			str = [[NSString alloc] initWithFormat:@"%u Byte(s)", captureLength];
			[ret addObject:@"Captured portion"];
			[ret addObject:str];
			[str release];
			return [ret autorelease];
			/* NOTREACHED */

		default:
			return [decoders objectAtIndex:fieldIndex - 3];
			/* NOTREACHED */
	}
}

- (unsigned int)numberOfValues
{
	return 0;
}

- (id)valueAtIndex:(int)anIndex
{
	return nil;
}

/* ColumnIdentifier protocol methods */

+ (NSArray *)columnIdentifiers
{
	ColumnIdentifier *colIdent;
	NSMutableArray *ret;
	unsigned int i;

	ret = [[NSMutableArray alloc] initWithCapacity:sizeof(names) / sizeof(names[0])];

	for(i = 0; i < sizeof(names) / sizeof(names[0]) ; ++i) {
		colIdent = [[ColumnIdentifier alloc] initWithDecoder:[self class] index:i longName:names[i][0] shortName:names[i][1]];
		[ret addObject:colIdent];
		[colIdent release];
	}

	return [ret autorelease];
}

- (NSString *)columnStringForIndex:(unsigned int)fieldIndex
{
	switch(fieldIndex) {
		case 0:
			return [NSString stringWithFormat:@"%u", [self number]];
		case 1:
			return [[self date] descriptionWithFormat:TABLEVIEW_DATE_FORMAT];
		case 2:
			return [self protocols];
		case 3:
			return [self info];
		case 4:
			return [NSString stringWithFormat:@"%u", [self captureLength]];
		case 5:
			return [NSString stringWithFormat:@"%u", [self actualLength]];
	}

	return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
	switch(fieldIndex) {
		case 0:
			return val_compare(number, ((Packet *)obj)->number);
		case 1:
			return [date compare:[obj date]];
		case 2:
			return [[self protocols] compare:[obj protocols]];
		case 3:
			return [[self info] compare:[obj info]];
		case 4:
			return val_compare(captureLength, ((Packet *)obj)->captureLength);
		case 5:
			return val_compare(actualLength, ((Packet *)obj)->actualLength);
	}

	return NSOrderedSame;
}

- (NSString *)stringForColumn:(ColumnIdentifier *)column
{
	id <ColumnIdentifier> decoder;

	if([column decoder] == [self class])
		return [self columnStringForIndex:[column index]];

	if((decoder = [self decoderForPlugin:[column plugin]]) == nil &&
	   (decoder = [self decoderForClass:[column decoder]]) == nil)
		 return nil;

	return [decoder columnStringForIndex:[column index]];
}

- (id)decoderForPlugin:(id <PPDecoderPlugin>)plugin
{
	PPPluginWrapper *pluginWrapper;
	unsigned int i;

	if(plugin == nil)
		return nil;

	i = [decoders count];

	while(i-- > 0) {
		if(![[decoders objectAtIndex:i] isMemberOfClass:[PPPluginWrapper class]])
			break;

		pluginWrapper = [decoders objectAtIndex:i];

		if([pluginWrapper plugin] == plugin)
			return pluginWrapper;
	}

	return nil;
}

- (BOOL)runFilterProgram:(PPBPFProgram *)filterProgram
{
	if([filterProgram program] == NULL)
		return YES;

	return (bpf_filter2([filterProgram program]->bf_insns, (unsigned char *)[data bytes], actualLength, captureLength) != 0) ? YES : NO;
}

@end
