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
#include <netinet/in.h>
#include <netinet/udp.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSArchiver.h>
#include "Packet.h"
#include "IPV4Decode.h"
#include "PortCache.h"
#include "pkt_compare.h"
#include "in_cksum.h"
#include "UDPDecode.h"

static NSString *names[][2] =	{{@"Source Port", @"UDP Src Port"},
								{@"Destination Port", @"UDP Dst Port"},
								{@"Header and Data Length", @"UDP Len"},
								{@"Checksum", @"UDP Cksum"},
								{@"Source Port Name", @"UDP Src Port *"},
								{@"Destination Port Name", @"UDP Dst Port *"}};

@implementation UDPDecode

- (id)initWithData:(NSData *)dataVal parent:(id <PPDecoderParent>)parentVal
{
	struct udphdr *hdr;

	if(dataVal == nil)
		return nil;

	if((self = [super init]) != nil) {
		/* not enough data is represented by returning nil */
		if([dataVal length] < UDPDECODE_HDR_MIN)
			goto err;

		parent = parentVal;

		hdr = (struct udphdr *)[dataVal bytes];

		sport = ntohs(hdr->uh_sport);
		dport = ntohs(hdr->uh_dport);
		len = ntohs(hdr->uh_ulen);
		sum = hdr->uh_sum;
	}
	return self;

	err:
		[self dealloc];
		return nil;
}

- (void)setParent:(id <PPDecoderParent>)parentVal
{
	parent = parentVal;
}

- (unsigned int)frontSize
{
	return sizeof(struct udphdr);
}

- (unsigned int)rearSize
{
	return 0;
}

- (Class)nextLayer
{
	return Nil;
}

+ (NSString *)shortName
{
	return @"UDP";
}

+ (NSString *)longName
{
	return @"UDP";
}

- (NSString *)info
{
	return [NSString stringWithFormat:@"%u to %u, %u B",
									  sport,
									  dport, len];
}

- (stacklev)level
{
	return SL_TRANSPORT;
}

- (unsigned int)srcPort
{
	return sport;
}

- (unsigned int)dstPort
{
	return dport;
}

- (NSString *)srcPortName
{
	NSString *ret;

	ret = [[PortCache sharedPortCache] serviceWithUDPPort:sport];

	if(ret == nil)
		ret = [NSString stringWithFormat:@"%u", sport];

	return ret;
}

- (NSString *)dstPortName
{
	NSString *ret;

	ret = [[PortCache sharedPortCache] serviceWithUDPPort:dport];

	if(ret == nil)
		ret = [NSString stringWithFormat:@"%u", dport];

	return ret;
}

- (BOOL)isChecksumValid
{
	return (sum == 0 || sum == [self computedChecksum]);
}

- (uint16_t)computedChecksum
{
	NSData *data;
	NSArray *decoders;
	IPV4Decode *ip;
	struct udphdr *hdr;
	unsigned int i;
	unsigned int skip_bytes;
	unsigned int partial_sum;
	uint16_t saved_sum;
	struct {
		struct in_addr src;
		struct in_addr dst;
		uint8_t zero;
		uint8_t proto;
		uint16_t len;
	} pseudo_hdr;

	if(calced_sum != 0)
		return calced_sum;

	if((ip = [parent decoderForClass:[IPV4Decode class]]) == nil)
		return 0;

	skip_bytes = 0;

	if((decoders = [parent decoders]) == nil)
		return 0;

	for(i = 0; i < [decoders count]; ++i) {
		id <Decode> current;
	
		if((current = [decoders objectAtIndex:i]) == self)
			break;

		skip_bytes += [current frontSize];
	}

	data = [parent packetData];

	if([data length] < skip_bytes || [data length] - skip_bytes < UDPDECODE_HDR_MIN)
		return 0;

	hdr = (struct udphdr *)((uint8_t *)[data bytes] + skip_bytes);

	saved_sum = hdr->uh_sum;
	hdr->uh_sum = 0;

	pseudo_hdr.src = [ip in_addrSrc];
	pseudo_hdr.dst = [ip in_addrDst];
	pseudo_hdr.zero = 0;
	pseudo_hdr.proto = [ip protocol];
	pseudo_hdr.len = hdr->uh_ulen; /* already network byte order */

	if(self->len > [data length] - skip_bytes)
		return 0;

	partial_sum = in_cksum_partial(&pseudo_hdr, sizeof(pseudo_hdr), 0);
	partial_sum = in_cksum_partial(hdr, self->len, partial_sum); // XXX what if packet is truncated, need to cap to real sz
	calced_sum = in_cksum_fold(partial_sum);

	hdr->uh_sum = saved_sum;

	return calced_sum;

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
			return [NSString stringWithFormat:@"%u", sport];
			/* NOTREACHED */

		case 1:
			return [NSString stringWithFormat:@"%u", dport];
			/* NOTREACHED */

		case 2:
			return [NSString stringWithFormat:@"%u B", len];
			/* NOTREACHED */

		case 3:
			return [NSString stringWithFormat:@"0x%.4x", sum];
			/* NOTREACHED */

		case 4:
			return [self srcPortName];
			/* NOTREACHED */

		case 5:
			return [self dstPortName];
			/* NOTREACHED */
	}

	return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
	switch(fieldIndex) {
		case 0:
			return val_compare(sport, ((UDPDecode *)obj)->sport);

		case 1:
			return val_compare(dport, ((UDPDecode *)obj)->dport);

		case 2:
			return val_compare(len, ((UDPDecode *)obj)->len);

		case 3:
			return val_compare(sum, ((UDPDecode *)obj)->sum);

		case 4:
			return [[[PortCache sharedPortCache] serviceWithUDPPort:sport] compare:
					[[PortCache sharedPortCache] serviceWithUDPPort:((UDPDecode *)obj)->sport]];

		case 5:
			return [[[PortCache sharedPortCache] serviceWithUDPPort:dport] compare:
					[[PortCache sharedPortCache] serviceWithUDPPort:((UDPDecode *)obj)->dport]];
	}

	return NSOrderedSame;
}

/* OutlineViewItem protocol methods */

- (BOOL)expandable
{
	return YES;
}

- (unsigned int)numberOfChildren
{
	return 4;
}

- (id)childAtIndex:(int)fieldIndex
{
	OutlineViewItem *ret;
	NSString *str;

	ret = [[OutlineViewItem alloc] init];
	[ret addObject:names[fieldIndex][0]];

	switch(fieldIndex) {
		case 0:
			str = [[NSString alloc] initWithFormat:@"%u", sport];
			[ret addObject:str];
			[str release];
			if((str = [[PortCache sharedPortCache] serviceWithUDPPort:sport]) == nil)
				str = @"Lookup failed";
			[ret addChildWithObjects:names[4][0], str, nil];
			break;

		case 1:
			str = [[NSString alloc] initWithFormat:@"%u", dport];
			[ret addObject:str];
			[str release];
			if((str = [[PortCache sharedPortCache] serviceWithUDPPort:dport]) == nil)
				str = @"Lookup failed";
			[ret addChildWithObjects:names[5][0], str, nil];
			break;

		case 2:
			str = [[NSString alloc] initWithFormat:@"%u Byte(s)", len];
			[ret addObject:str];
			[str release];
			break;

		case 3:
			if(sum == [self computedChecksum])
				str = [[NSString alloc] initWithFormat:@"0x%.4x (correct)", sum];
			else
				str = [[NSString alloc] initWithFormat:@"0x%.4x (incorrect, should be 0x%.4x)", sum, [self computedChecksum]];
			[ret addObject:str];
			[str release];
			break;

		default:
			[ret release];
			return nil;
	}

	return [ret autorelease];
}

- (unsigned int)numberOfValues
{
	return 1;
}

- (id)valueAtIndex:(int)anIndex
{
	return [[self class] longName];
}

/* NSCoding protocol methods */

- (void)encodeWithCoder:(NSCoder *)coder
{
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&sport];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&dport];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&len];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&sum];
}

- (id)initWithCoder:(NSCoder *)coder
{
	if((self = [super init]) != nil) {
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&sport];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&dport];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&len];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&sum];
		calced_sum = 0;
	}
	return self;
}

@end
