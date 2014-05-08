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
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stddef.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#import <Foundation/NSHost.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSArchiver.h>
#include "Packet.h"
#include "PPPluginManager.h"
#include "PPDecoderPlugin.h"
#include "UDPDecode.h"
#include "TCPDecode.h"
#include "HostCache.hh"
#include "ColumnIdentifier.h"
#include "strfuncs.h"
#include "pkt_compare.h"
#include "IPV6Decode.h"

static NSString *names[][2] =
    {{@"Version", @"IPv6 Ver"},
    {@"Traffic class", @"IPv6 T.Class"},
    {@"Flow label", @"IPv6 Flow ID"},
    {@"Payload length", @"IPv6 Pay. Len"},
    {@"Next header", @"IPv6 Next Hdr"},
    {@"Hop limit", @"IPv6 Hop Lim"},
    {@"Source IP6 Address", @"Src IP6"},
    {@"Destination IP6 Address", @"Dst IP6"},
    {@"Source Hostname", @"Src Host IP6"},
    {@"Destination Hostname", @"Dst Host IP6"}};

static inline unsigned int ip6_get_version(const struct ip6_hdr* hdr)
{
    return (ntohl(hdr->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xF0000000) >> 28;
}

static inline unsigned int ip6_get_traffic_class(const struct ip6_hdr* hdr)
{
    return (ntohl(hdr->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0FF00000) >> 20;
}

static inline unsigned int ip6_get_flow_label(const struct ip6_hdr* hdr)
{
    return ntohl(hdr->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000FFFFF;
}

static inline unsigned int ip6_get_payload_length(const struct ip6_hdr* hdr)
{
    return ntohs(hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
}

static inline unsigned int ip6_get_next_header(const struct ip6_hdr* hdr)
{
    return hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
}

static inline unsigned int ip6_get_hop_limit(const struct ip6_hdr* hdr)
{
    return hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
}

@implementation IPV6Decode

- (id)initWithData:(NSData *)data parent:(id <PPDecoderParent>)parent
{
    if(data == nil || [data length] < sizeof(struct ip6_hdr) || (self = [super init]) == nil)
        return nil;

    m_hdr = (struct ip6_hdr*)[data bytes];
    m_parent = parent;

    return self;
}

- (void)setParent:(id <PPDecoderParent>)parent
{
    m_parent = parent;
    m_hdr = (struct ip6_hdr*)[m_parent packetData];
}

- (unsigned int)frontSize
{
    // TODO: Support extension headers:
    //
    // IPPROTO_HOPOPTS = 0
    // IPPROTO_ROUTING = 43
    // IPPROTO_FRAGMENT = 44
    // IPPROTO_AH = 51 (authentication header)
    // IPPROTO_ESP = 50 (encapsulating security payload)
    // IPPROTO_NONE = 59
    // IPPROTO_DSTOPTS = 60
    return sizeof(struct ip6_hdr);
}

- (unsigned int)rearSize
{
	return 0;
}

- (Class)nextLayer
{
    switch(m_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        case IPPROTO_TCP:
            return [TCPDecode class];
        case IPPROTO_UDP:
            return [UDPDecode class];
    }
    return Nil;
}

+ (NSString *)shortName
{
    return @"IPv6";
}

+ (NSString *)longName
{
    return @"IP Version 6";
}

- (NSString *)info
{
    return [NSString stringWithFormat:@"%@ to %@, %uB total", [self from], [self to], [self length]];
}

- (NSString *)addrTo
{
    return ipaddrstr(&m_hdr->ip6_dst, sizeof(struct in6_addr));
}

- (NSString *)addrFrom
{
    return ipaddrstr(&m_hdr->ip6_src, sizeof(struct in6_addr));
}

- (NSString *)resolvTo
{
    return [[m_parent hostCache] hostWithIp6AddressASync:&m_hdr->ip6_dst returnCode:NULL];
}

- (NSString *)resolvFrom
{
    return [[m_parent hostCache] hostWithIp6AddressASync:&m_hdr->ip6_src returnCode:NULL];
}

- (NSString *)to
{
    NSString *ret;

    if((ret = [self resolvTo]) == nil)
        ret = [self addrTo];

    return ret;
}

- (NSString *)from
{
    NSString *ret;

    if((ret = [self resolvFrom]) == nil)
        ret = [self addrFrom];

    return ret;
}

- (uint8_t)nextHeader
{
    return ip6_get_next_header(m_hdr);
}

- (unsigned int)length
{
    return ip6_get_payload_length(m_hdr) + sizeof(struct ip6_hdr);
}

- (unsigned int)headerLength
{
	return [self frontSize];
}

- (struct in6_addr)in6_addrSrc
{
    return m_hdr->ip6_src;
}

- (struct in6_addr)in6_addrDst
{
    return m_hdr->ip6_dst;
}

- (id <OutlineViewItem>)resolvCallback:(void *)data
{
	OutlineViewItem *ret;
	NSString *resolved;
	int retcode;

	ret = [[OutlineViewItem alloc] init];

	[ret addObject:@"Hostname"];

	if((resolved = [[m_parent hostCache] hostWithIp6AddressASync:data returnCode:&retcode]) == nil) {
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

	return [ret autorelease];
}

- (stacklev)level
{
    return SL_NETWORK;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"[IP6: %@ to %@]", [self from], [self to]];
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
            return [NSString stringWithFormat:@"%u", ip6_get_version(m_hdr)];
        case 1:
            return [NSString stringWithFormat:@"%u", ip6_get_traffic_class(m_hdr)];
        case 2:
            return [NSString stringWithFormat:@"%u", ip6_get_flow_label(m_hdr)];
        case 3:
            return [NSString stringWithFormat:@"%u", ip6_get_payload_length(m_hdr)];
        case 4:
            return [NSString stringWithFormat:@"%u", ip6_get_next_header(m_hdr)];
        case 5:
            return [NSString stringWithFormat:@"%u", ip6_get_hop_limit(m_hdr)];
        case 6:
            return ipaddrstr(&m_hdr->ip6_src, sizeof(struct in6_addr));
        case 7:
            return ipaddrstr(&m_hdr->ip6_dst, sizeof(struct in6_addr));
        case 8:
            return ipaddrstr(&m_hdr->ip6_src, sizeof(struct in6_addr));
        case 9:
            return ipaddrstr(&m_hdr->ip6_dst, sizeof(struct in6_addr));
    }
    return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
    const struct ip6_hdr *other = ((IPV6Decode *)obj)->m_hdr;

    switch(fieldIndex) {
        case 0:
            return val_compare(ip6_get_version(m_hdr), ip6_get_version(other));
        case 1:
            return val_compare(ip6_get_traffic_class(m_hdr), ip6_get_traffic_class(other));
        case 2:
            return val_compare(ip6_get_flow_label(m_hdr), ip6_get_flow_label(other));
        case 3:
            return val_compare(ip6_get_payload_length(m_hdr), ip6_get_payload_length(other));
        case 4:
            return val_compare(ip6_get_next_header(m_hdr), ip6_get_next_header(other));
        case 5:
            return val_compare(ip6_get_version(m_hdr), ip6_get_version(other));
        case 6:
            return mem_compare(&m_hdr->ip6_src, &other->ip6_src, sizeof(struct in6_addr));
        case 7:
            return mem_compare(&m_hdr->ip6_dst, &other->ip6_dst, sizeof(struct in6_addr));
        case 8:
           return [[self resolvFrom] compare:[obj resolvFrom]];
        case 9:
           return [[self resolvTo] compare:[obj resolvTo]];
    }

    return NSOrderedSame;
}

/* OutlineView protocol methods */

- (BOOL)expandable
{
    return YES;
}

- (unsigned int)numberOfChildren
{
    return 8;
}

- (id)childAtIndex:(int)fieldIndex
{
    OutlineViewItem *ret;
    NSString *str;

    ret = [[OutlineViewItem alloc] init];
    [ret addObject:names[fieldIndex][0]];

    switch(fieldIndex) {
        case 0:
            str = [[NSString alloc] initWithFormat:@"%u", ip6_get_version(m_hdr)];
            [ret addObject:str];
            [str release];
            break;
        case 1:
            str = [[NSString alloc] initWithFormat:@"%u", ip6_get_traffic_class(m_hdr)];
            [ret addObject:str];
            [str release];
            break;
        case 2:
            str = [[NSString alloc] initWithFormat:@"%u", ip6_get_flow_label(m_hdr)];
            [ret addObject:str];
            [str release];
            break;
        case 3:
            str = [[NSString alloc] initWithFormat:@"%u", ip6_get_payload_length(m_hdr)];
            [ret addObject:str];
            [str release];
            break;
        case 4:
            str = [[NSString alloc] initWithFormat:@"%u", ip6_get_next_header(m_hdr)];
            [ret addObject:str];
            [str release];
            break;
        case 5:
            str = [[NSString alloc] initWithFormat:@"%u", ip6_get_hop_limit(m_hdr)];
            [ret addObject:str];
            [str release];
            break;
		case 6:
			[ret addObject:[self addrFrom]];
			[ret addChildWithCallback:self selector:@selector(resolvCallback:) data:&m_hdr->ip6_src];
			break;
		case 7:
			[ret addObject:[self addrTo]];
			[ret addChildWithCallback:self selector:@selector(resolvCallback:) data:&m_hdr->ip6_dst];
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

- (void)encodeWithCoder:(NSCoder *)coder
{
}

- (id)initWithCoder:(NSCoder *)coder
{
    if((self = [super init]) != nil) {
        m_parent = nil;
        m_hdr = NULL;
    }
    return self;
}

- (void)dealloc
{
    [super dealloc];
}

@end
