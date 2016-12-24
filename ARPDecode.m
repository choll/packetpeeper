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
#include <net/if_arp.h>
#include <string.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSArchiver.h>
#include "Packet.h"
#include "HostCache.hh"
#include "OUICache.h"
#include "strfuncs.h"
#include "pkt_compare.h"
#include "ARPDecode.h"

static	NSString *arp_names[][2] =	{{@"Hardware Address Type", @"ARP HW Type"},
									{@"Protocol Address Type", @"ARP Prot Type"},
									{@"Hardware Address Size", @"ARP HW Len"},
									{@"Protocol Address Size", @"ARP Prot Len"},
									{@"Operation", @"ARP Op"},
									{@"Sender Ethernet", @"ARP Snd Eth"},
									{@"Sender IP", @"ARP Snd IP"},
									{@"Target Ethernet", @"ARP Tgt Eth"},
									{@"Target IP", @"ARP Tgt IP"},
									/* XXX Todo; hw/prot type meanings */
									{@"Operation Meaning", @"ARP Op *"},
									{@"Sender Hostname", @"ARP Snd Host"},
									{@"Target Hostname", @"ARP Tgt Host"},
									{@"Sender Ethernet Manufacturer", @"ARP Snd Eth Manuf"},
									{@"Target Ethernet Manufacturer", @"ARP Tgt Eth Manuf"}};

static	NSString *rarp_names[][2] =	{{@"Hardware Address Type", @"RARP HW Type"},
									{@"Protocol Address Type", @"RARP Prot Type"},
									{@"Hardware Address Size", @"RARP HW Len"},
									{@"Protocol Address Size", @"RARP Prot Len"},
									{@"Operation", @"RARP Op"},
									{@"Operation Meaning", @"RARP Op *"},
									{@"Sender Ethernet", @"RARP Snd Eth"},
									{@"Sender IP", @"RARP Snd IP"},
									{@"Target Ethernet", @"RARP Tgt Eth"},
									{@"Target IP", @"RARP Tgt IP"},
									{@"Sender Hostname", @"RARP Snd Host"},
									{@"Target Hostname", @"RARP Tgt Host"},
									{@"Sender Ethernet Manufacturer", @"RARP Snd Eth Manuf"},
									{@"Target Ethernet Manufacturer", @"RARP Tgt Eth Manuf"}};

@implementation ARPDecode

- (id)initWithData:(NSData *)dataVal parent:(id <PPDecoderParent>)parentVal
{
	struct arphdr *hdr;

	if(dataVal == nil)
		return nil;

	if((self = [super init]) != nil) {
		parent = parentVal;

		/* not enough data is represented by returning nil */
		if([dataVal length] < ARPDECODE_HDR_MIN)
			goto err;

		hdr = (struct arphdr *)[dataVal bytes];

		hardtype = ntohs(hdr->ar_hrd);
		prottype = ntohs(hdr->ar_pro);
		hardsz = hdr->ar_hln;
		protsz = hdr->ar_pln;
		op = ntohs(hdr->ar_op);

		if(hardtype == ARPHRD_ETHER && hardsz == ETHER_ADDR_LEN) {
			(void)memcpy(ethsender, (void *)((uintptr_t)hdr + ARP_FIELD_SZ), sizeof(ethsender)); // pull back by 4 bytes?
			(void)memcpy(ethtarget, (void *)((uintptr_t)hdr + ARP_FIELD_SZ + ETHER_ADDR_LEN + protsz), sizeof(ethtarget));
		}

		if(prottype == ETHERTYPE_IP && protsz == sizeof(struct in_addr)) {
			(void)memcpy(&ipsender, (void *)((uintptr_t)hdr + ARP_FIELD_SZ + hardsz), sizeof(ipsender));
			(void)memcpy(&iptarget, (void *)((uintptr_t)hdr + ARP_FIELD_SZ + (hardsz * 2) + sizeof(struct in_addr)), sizeof(iptarget));
		}
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

- (size_t)frontSize
{
	return sizeof(struct arphdr) + (hardsz * 2) + (protsz * 2);
}

- (size_t)rearSize
{
	return 0;
}

- (Class)nextLayer
{
	return Nil;
}

+ (NSString *)shortName
{
	return @"ARP";
}

+ (NSString *)longName
{
	return @"ARP";
}

- (NSString *)info
{
	switch(op) {
		case ARPOP_REQUEST:
			return [NSString stringWithFormat:@"Who has %@? Tell %@", [self target], [self sender]];

		case ARPOP_REPLY:
			return [NSString stringWithFormat:@"%@ is at %@", [self sender], [self senderEther]];

		case ARPOP_REVREQUEST:
			return [NSString stringWithFormat:@"Who is %@? Tell %@", [self targetEther], [self senderEther]];

		case ARPOP_REVREPLY:
			return [NSString stringWithFormat:@"%@ is at %@", [self targetEther], [self target]];
	}

	return [NSString stringWithFormat:@"Op %u (unknown)", op];
}

- (NSString *)sender
{
	NSString *ret;

	if((ret = [self resolvSender]) != nil)
		return ret;
	else if((ret = [self senderIP]) != nil)
		return ret;
	else
		return @"(Unknown)";
}

- (NSString *)target
{
	NSString *ret;

	if((ret = [self resolvTarget]) != nil)
		return ret;
	else if((ret = [self targetIP]) != nil)
		return ret;
	else
		return @"(Unknown)";
}

- (NSString *)senderEther
{
	if(hardtype == ARPHRD_ETHER && hardsz == ETHER_ADDR_LEN)
		return etherstr(ethsender, sizeof(ethsender));
	else
		return @"(Unknown)";
}

- (NSString *)targetEther
{
	if(hardtype == ARPHRD_ETHER && hardsz == ETHER_ADDR_LEN)
		return etherstr(ethtarget, sizeof(ethtarget));
	else
		return @"(Unknown)";
}

- (NSString *)senderIP
{
	/* only IPv4 supported for now */
	if(prottype == ETHERTYPE_IP && protsz == sizeof(struct in_addr))
		return ipaddrstr(&ipsender, sizeof(ipsender));
	else
		return nil;
}

- (NSString *)targetIP
{
	if(prottype == ETHERTYPE_IP && protsz == sizeof(struct in_addr))
		return ipaddrstr(&iptarget, sizeof(iptarget));
	else
		return nil;
}

- (NSString *)resolvSender
{
	if(prottype == ETHERTYPE_IP && protsz == sizeof(struct in_addr))
		return [[parent hostCache] hostWithAddressASync:&ipsender returnCode:NULL];
	else
		return nil;
}

- (NSString *)resolvTarget
{
	if(prottype == ETHERTYPE_IP && protsz == sizeof(struct in_addr))
		return [[parent hostCache] hostWithAddressASync:&iptarget returnCode:NULL];
	else
		return nil;
}

- (id <OutlineViewItem>)resolvCallback:(void *)data
{
	OutlineViewItem *ret;
	NSString *resolved;
	int retcode;

	ret = [[OutlineViewItem alloc] init];

	if(prottype == ETHERTYPE_IP && protsz == sizeof(struct in_addr)) {
		[ret addObject:@"Hostname"];

		if((resolved = [[parent hostCache] hostWithAddressASync:data returnCode:&retcode]) == nil) {
			switch(retcode) {
				case HOSTCACHE_NONAME:
					[ret addObject:@"Lookup failed"];
					break;

				case HOSTCACHE_INPROG:
					[ret addObject:@"Lookup in progress"];
					break;

				default:
					[ret addObject:@"Lookup error"];
					break;
			}
		} else
			[ret addObject:resolved];
	} else
		ret = nil;

	return [ret autorelease];
}

- (NSString *)operationString
{
	switch(op) {
		case ARPOP_REQUEST:
			return @"ARP Request";

		case ARPOP_REPLY:
			return @"ARP Reply";

		case ARPOP_REVREQUEST:
			return @"RARP Request";

		case ARPOP_REVREPLY:
			return @"RARP Reply";

		default:
			return @"Unknown";
	}
}

- (id <OutlineViewItem>)operationStringCallback:(void *)data
{
	OutlineViewItem *ret;

	ret = [[OutlineViewItem alloc] init];
	[ret addObject:[self operationString]];

	return [ret autorelease];
}

- (stacklev)level
{
	return SL_DATALINK;
}

/* ColumnIdentifier protocol methods */

+ (NSArray *)columnIdentifiers
{
	ColumnIdentifier *colIdent;
	NSMutableArray *ret;
	unsigned int i;

	ret = [[NSMutableArray alloc] initWithCapacity:sizeof(arp_names) / sizeof(arp_names[0])];

	for(i = 0; i < sizeof(arp_names) / sizeof(arp_names[0]) ; ++i) {
		colIdent = [[ColumnIdentifier alloc] initWithDecoder:[self class] index:i longName:arp_names[i][0] shortName:arp_names[i][1]];
		[ret addObject:colIdent];
		[colIdent release];
	}

	return [ret autorelease];
}

- (NSString *)columnStringForIndex:(unsigned int)fieldIndex
{
	switch(fieldIndex) {
		case 0:
			return [NSString stringWithFormat:@"0x%.4x", hardtype];
			/* NOTREACHED */

		case 1:
			return [NSString stringWithFormat:@"0x%.4x", prottype];
			/* NOTREACHED */

		case 2:
			return [NSString stringWithFormat:@"%u B", hardsz];
			/* NOTREACHED */

		case 3:
			return [NSString stringWithFormat:@"%u B", protsz];
			/* NOTREACHED */

		case 4:
 			return [NSString stringWithFormat:@"%u", op];
			/* NOTREACHED */

		case 5:
			return [self senderEther];
			/* NOTREACHED */

		case 6:
			return [self senderIP];
			/* NOTREACHED */

		case 7:
			return [self targetEther];
			/* NOTREACHED */

		case 8:
			return [self targetIP];
			/* NOTREACHED */

		case 9:
			return [self operationString];
			/* NOTREACHED */

		case 13:
			return [self sender];
			/* NOTREACHED */

		case 14:
			return [self target];
			/* NOTREACHED */

		case 15:
			if(hardtype == ARPHRD_ETHER && hardsz == ETHER_ADDR_LEN)
				return [[OUICache sharedOUICache] manufacturerForEthernetAddress:ethsender];
			else
				return @"Unknown hardware";
			/* NOTREACHED */

		case 16:
			if(hardtype == ARPHRD_ETHER && hardsz == ETHER_ADDR_LEN)
				return [[OUICache sharedOUICache] manufacturerForEthernetAddress:ethtarget];
			else
				return @"Unknown hardware";
			/* NOTREACHED */
	}

	return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
	switch(fieldIndex) {
		case 0:
			return val_compare(hardtype, ((ARPDecode *)obj)->hardtype);

		case 1:
			return val_compare(prottype, ((ARPDecode *)obj)->prottype);

		case 2:
			return val_compare(hardsz, ((ARPDecode *)obj)->hardsz);

		case 3:
			return val_compare(protsz, ((ARPDecode *)obj)->protsz);

		case 4:
			return val_compare(op, ((ARPDecode *)obj)->op);

		case 5:
			return mem_compare(ethsender, ((ARPDecode *)obj)->ethsender, sizeof(ethsender));
			/* NOTREACHED */

		case 6:
			return mem_compare(&ipsender, (&((ARPDecode *)obj)->ipsender), sizeof(ipsender));
			/* NOTREACHED */

		case 7:
			return mem_compare(ethtarget, ((ARPDecode *)obj)->ethtarget, sizeof(ethtarget));
			/* NOTREACHED */

		case 8:
			return mem_compare(&iptarget, (&((ARPDecode *)obj)->iptarget), sizeof(iptarget));
			/* NOTREACHED */

		case 9:
			return [[self operationString] compare:[obj operationString]];
			/* NOTREACHED */

		case 10:
			return [[self resolvSender] compare:[obj resolvSender]];
			/* NOTREACHED */

		case 11:
			return [[self resolvTarget] compare:[obj resolvTarget]];
			/* NOTREACHED */

		case 12:
			return [[self sender] compare:[obj sender]];
			/* NOTREACHED */

		case 13:
			return [[self target] compare:[obj target]];
			/* NOTREACHED */

		case 14:
			if(hardtype == ARPHRD_ETHER && hardsz == ETHER_ADDR_LEN)
				return [[[OUICache sharedOUICache] manufacturerForEthernetAddress:ethsender] compare:[[OUICache sharedOUICache] manufacturerForEthernetAddress:((ARPDecode *)obj)->ethsender]];
			break;

		case 15:
			if(hardtype == ARPHRD_ETHER && hardsz == ETHER_ADDR_LEN)
				return [[[OUICache sharedOUICache] manufacturerForEthernetAddress:ethtarget] compare:[[OUICache sharedOUICache] manufacturerForEthernetAddress:((ARPDecode *)obj)->ethtarget]];
			break;
	}

	return NSOrderedSame;
}

/* OutlineViewItem protocol methods */

- (BOOL)expandable
{
	return YES;
}

- (size_t)numberOfChildren
{
	return 9;
}

- (id)childAtIndex:(int)fieldIndex
{
	OutlineViewItem *ret;
	NSString *str;

	ret = [[OutlineViewItem alloc] init];
	[ret addObject:arp_names[fieldIndex][0]];

	switch(fieldIndex) {
		case 0:
			str = [[NSString alloc] initWithFormat:@"0x%.4x", hardtype];
			[ret addObject:str];
			[str release];
			break;

		case 1:
			/* needs to be expandable */
			str = [[NSString alloc] initWithFormat:@"0x%.4x", prottype];
			[ret addObject:str];
			[str release];
			break;

		case 2:
			str = [[NSString alloc] initWithFormat:@"%u Byte(s)", hardsz];
			[ret addObject:str];
			[str release];
			break;

		case 3:
			str = [[NSString alloc] initWithFormat:@"%u Byte(s)", protsz];
			[ret addObject:str];
			[str release];
			break;

		case 4:
			str = [[NSString alloc] initWithFormat:@"%u", op];
			[ret addObject:str];
			[str release];
			[ret addChildWithCallback:self selector:@selector(operationStringCallback:) data:NULL];
			break;

		case 5:
			[ret addObject:[self senderEther]];
			if((str = [[OUICache sharedOUICache] manufacturerForEthernetAddress:ethsender]) == nil)
				str = @"Lookup failed";
			[ret addChildWithObjects:arp_names[14][0], str, nil];
			break;

		case 6:
			[ret addObject:[self senderIP]];
			[ret addChildWithCallback:self selector:@selector(resolvCallback:) data:&ipsender];
			break;

		case 7:
			[ret addObject:[self targetEther]];
			if((str = [[OUICache sharedOUICache] manufacturerForEthernetAddress:ethtarget]) == nil)
				str = @"Lookup failed";
			[ret addChildWithObjects:arp_names[15][0], str, nil];
			break;

		case 8:
			[ret addObject:[self targetIP]];
			[ret addChildWithCallback:self selector:@selector(resolvCallback:) data:&iptarget];
			break;

		default:
			[ret release];
			return nil;
	}

	return [ret autorelease];
}

- (size_t)numberOfValues
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
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&hardtype];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&prottype];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&hardsz];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&protsz];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&op];
	[coder encodeArrayOfObjCType:@encode(unsigned char) count:sizeof(ethsender) at:ethsender];
	[coder encodeValueOfObjCType:@encode(struct in_addr) at:&ipsender];
	[coder encodeArrayOfObjCType:@encode(unsigned char) count:sizeof(ethtarget) at:ethtarget];
	[coder encodeValueOfObjCType:@encode(struct in_addr) at:&iptarget];
}

- (id)initWithCoder:(NSCoder *)coder
{
	if((self = [super init]) != nil) {
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&hardtype];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&prottype];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&hardsz];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&protsz];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&op];
		[coder decodeArrayOfObjCType:@encode(unsigned char) count:sizeof(ethsender) at:ethsender];
		[coder decodeValueOfObjCType:@encode(struct in_addr) at:&ipsender];
		[coder decodeArrayOfObjCType:@encode(unsigned char) count:sizeof(ethtarget) at:ethtarget];
		[coder decodeValueOfObjCType:@encode(struct in_addr) at:&iptarget];
		parent = nil;
	}
	return self;
}

@end

@implementation RARPDecode

+ (NSString *)shortName
{
	return @"RARP";
}

+ (NSString *)longName
{
	return @"RARP";
}

+ (NSArray *)columnIdentifiers
{
	ColumnIdentifier *colIdent;
	NSMutableArray *ret;
	unsigned int i;

	ret = [[NSMutableArray alloc] initWithCapacity:sizeof(rarp_names) / sizeof(rarp_names[0])];

	for(i = 0; i < sizeof(rarp_names) / sizeof(rarp_names[0]) ; ++i) {
		colIdent = [[ColumnIdentifier alloc] initWithDecoder:[self class] index:i longName:rarp_names[i][0] shortName:rarp_names[i][1]];
		[ret addObject:colIdent];
		[colIdent release];
	}

	return [ret autorelease];
}

@end
