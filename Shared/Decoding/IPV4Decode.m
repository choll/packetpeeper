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

#include "IPV4Decode.h"
#include "../../PacketPeeper/HostCache.hh"
#include "../../PacketPeeper/Plugins/PPDecoderPlugin.h"
#include "../../PacketPeeper/Plugins/PPPluginManager.h"
#include "../../PacketPeeper/UI Classes/pkt_compare.h"
#include "ICMPDecode.h"
#include "Packet.h"
#include "TCPDecode.h"
#include "UDPDecode.h"
#include "in_cksum.h"
#include "strfuncs.h"
#import <Foundation/NSArchiver.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#import <Foundation/NSHost.h>
#import <Foundation/NSString.h>
#include <machine/endian.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static NSString* names[][2] = {{@"Version", @"IPv4 Ver"},
                               {@"Header length", @"IPv4 Hdr Len"},
                               {@"Type of service", @"IPv4 TOS"},
                               {@"Total length", @"IPv4 Len"},
                               {@"Identification", @"IPv4 Ident"},
                               {@"Flags", @"IPv4 Flags"},
                               {@"Fragment Offset", @"IPv4 Frag"},
                               {@"Time To Live", @"IPv4 TTL"},
                               {@"Protocol Type", @"IPv4 Proto"},
                               {@"Checksum", @"IPv4 Cksum"},
                               {@"Source IP Address", @"Src IP"},
                               {@"Destination IP Address", @"Dst IP"},
                               {@"Options", @"IPv4 Options"},
                               {@"Source Hostname", @"Src Host"},
                               {@"Destination Hostname", @"Dst Host"},
                               {@"Flags Meaning", @"IPv4 Flags *"}};

@implementation IPV4Decode

- (id)initWithData:(NSData*)dataVal parent:(id<PPDecoderParent>)parentVal
{
    struct ip* hdr;

    if (dataVal == nil)
        return nil;

    if ((self = [super init]) != nil)
    {
        parent = parentVal;

        if ([dataVal length] < IPV4DECODE_HDR_MIN)
            goto err;

        /* n.b. all fields in network byte order (so convert anything 2 WHOLE bytes or more) */
        hdr = (struct ip*)[dataVal bytes];

        /* perhaps just note to the user that this is invalid, process no options
           and set nextLayer to Nil. */
        if (hdr->ip_hl < 5 || (hdr->ip_hl * 4) > [dataVal length])
            goto err;

        version = hdr->ip_v;
        hlen = hdr->ip_hl;
        tos = hdr->ip_tos;
        tlen = ntohs(hdr->ip_len);
        ident = ntohs(hdr->ip_id);
        flags = (hdr->ip_off & ~IP_OFFMASK) >> 8;
        offset = ntohs(hdr->ip_off & IP_OFFMASK);
        ttl = hdr->ip_ttl;
        proto = hdr->ip_p;
        sum = hdr->ip_sum;
        calced_sum = 0;
        src = hdr->ip_src;
        dst = hdr->ip_dst;
        optionsDecoder = nil;
    }

    return self;

err:
    [self dealloc];
    return nil;
}

- (void)setParent:(id<PPDecoderParent>)parentVal
{
    parent = parentVal;
}

- (size_t)frontSize
{
    return hlen * 4; /* hlen is measured in 32bit words, maximum value is 60 */
}

- (size_t)rearSize
{
    return 0;
}

- (Class)nextLayer
{
    switch (proto)
    {
    case IPPROTO_ICMP:
        return [ICMPDecode class];
        /* NOTREACHED */

        //		case IPPROTO_IGMP:
        //			nextLayer = [IGMPDecode class]
        //			break;

    case IPPROTO_TCP:
        return [TCPDecode class];
        /* NOTREACHED */

    case IPPROTO_UDP:
        return [UDPDecode class];
        /* NOTREACHED */
    }
    return Nil;
}

+ (NSString*)shortName
{
    return @"IPv4";
}

+ (NSString*)longName
{
    return @"IP Version 4";
}

- (NSString*)info
{
    return [NSString
        stringWithFormat:@"%@ to %@, %zuB total%s",
                         [self from],
                         [self to],
                         [self length],
                         [self isChecksumValid] ? "" : " (bad checksum)"];
}

- (NSString*)addrTo
{
    return ipaddrstr(&dst, sizeof(dst));
}

- (NSString*)addrFrom
{
    return ipaddrstr(&src, sizeof(src));
}

- (NSString*)resolvTo
{
    return [[parent hostCache] hostWithAddressASync:&dst returnCode:NULL];
}

- (NSString*)resolvFrom
{
    return [[parent hostCache] hostWithAddressASync:&src returnCode:NULL];
}

- (NSString*)to
{
    NSString* ret;

    if ((ret = [self resolvTo]) == nil)
        ret = [self addrTo];

    return ret;
}

- (NSString*)from
{
    NSString* ret;

    if ((ret = [self resolvFrom]) == nil)
        ret = [self addrFrom];

    return ret;
}

- (uint8_t)protocol
{
    return proto;
}

- (BOOL)isChecksumValid
{
    return (sum == 0 || sum == [self computedChecksum]);
}

- (uint16_t)computedChecksum
{
    NSData* data;
    struct ip* hdr;
    size_t skip_bytes;
    size_t hdr_nbytes;
    uint16_t saved_sum;

    if (calced_sum != 0)
        return calced_sum;

    skip_bytes = [parent byteOffsetForDecoder:self];
    data = [parent packetData];

    if ([data length] < skip_bytes ||
        [data length] - skip_bytes < IPV4DECODE_HDR_MIN)
        return 0;

    hdr = (struct ip*)((uint8_t*)[data bytes] + skip_bytes);

    hdr_nbytes = hdr->ip_hl * 4;

    if ([data length] - skip_bytes < hdr_nbytes)
        return 0;

    saved_sum = hdr->ip_sum;
    hdr->ip_sum = 0;

    calced_sum = in_cksum_fold(in_cksum_partial(hdr, hdr_nbytes, 0));

    hdr->ip_sum = saved_sum;

    return calced_sum;
}

- (NSString*)flagsMeaning
{
    NSString* flag_names[] = {
        @"Reserved", @"Don't Fragment", @"More Fragments"};
    NSMutableString* ret;
    unsigned int i;

    ret = nil;

    for (i = 0; i < (sizeof(flag_names) / sizeof(flag_names[0])); ++i)
    {
        if (flags & (1 << (7 - i)))
        {
            if (ret == nil)
                ret = [[NSMutableString alloc] initWithString:flag_names[i]];
            else
                [ret appendFormat:@", %@", flag_names[i]];
        }
    }

    if (ret == nil)
        return @"None";

    return [ret autorelease];
}

- (BOOL)dontFragmentFlag
{
    return (flags & IPV4DECODE_FLAGS_DFRAG) != 0;
}

- (BOOL)moreFragmentsFlag
{
    return (flags & IPV4DECODE_FLAGS_MFRAG) != 0;
}

- (unsigned int)fragmentOffset
{
    return offset;
}

- (size_t)length
{
    return tlen;
}

- (size_t)headerLength
{
    return [self frontSize];
}

- (struct in_addr)in_addrSrc
{
    return src;
}

- (struct in_addr)in_addrDst
{
    return dst;
}

- (NSData*)optionsData
{
    NSData* data;
    size_t nbytes;

    if ((data = [parent dataForDecoder:self]) == nil)
        return nil;

    if ([data length] <= IPV4DECODE_HDR_MIN)
        return nil;

    nbytes = (hlen * 4) - IPV4DECODE_HDR_MIN;

    if ([data length] < nbytes)
        nbytes = [data length];

    return [NSData
        dataWithBytesNoCopy:((uint8_t*)[data bytes] + IPV4DECODE_HDR_MIN)
                     length:nbytes
               freeWhenDone:NO];
}

- (id<OutlineViewItem>)resolvCallback:(void*)data
{
    OutlineViewItem* ret;
    NSString* resolved;
    int retcode;

    ret = [[OutlineViewItem alloc] init];

    [ret addObject:@"Hostname"];

    if ((resolved = [[parent hostCache] hostWithAddressASync:data
                                                  returnCode:&retcode]) == nil)
    {
        switch (retcode)
        {
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
    }
    else
        [ret addObject:resolved];

    return [ret autorelease];
}

- (stacklev)level
{
    return SL_NETWORK;
}

- (NSString*)description
{
    return
        [NSString stringWithFormat:@"[IP: %@ to %@]", [self from], [self to]];
}

/* ColumnIdentifier protocol methods */

+ (NSArray*)columnIdentifiers
{
    ColumnIdentifier* colIdent;
    NSMutableArray* ret;
    unsigned int i;

    ret = [[NSMutableArray alloc]
        initWithCapacity:sizeof(names) / sizeof(names[0])];

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    {
        colIdent = [[ColumnIdentifier alloc] initWithDecoder:[self class]
                                                       index:i
                                                    longName:names[i][0]
                                                   shortName:names[i][1]];
        [ret addObject:colIdent];
        [colIdent release];
    }

    return [ret autorelease];
}

- (NSString*)columnStringForIndex:(unsigned int)fieldIndex
{
    switch (fieldIndex)
    {
    case 0:
        return [NSString stringWithFormat:@"%u", version];
    case 1:
        return [NSString stringWithFormat:@"%u (%u B)", hlen, hlen * 4];
    case 2:
        return [NSString stringWithFormat:@"0x%.2x", tos];
    case 3:
        return [NSString stringWithFormat:@"%u B", tlen];
    case 4:
        return [NSString stringWithFormat:@"%u", ident];
    case 5:
        return binstr(&flags, 3);
    case 6:
        return [NSString stringWithFormat:@"%u (%u B)", offset, offset * 8];
    case 7:
        return [NSString stringWithFormat:@"%u hop(s)", ttl];
    case 8:
        /* needs to be looked up */
        return [NSString stringWithFormat:@"0x%.2x", proto];
    case 9:
        return [NSString stringWithFormat:@"0x%.4x", sum];
    case 10:
        return [self addrFrom];
    case 11:
        return [self addrTo];
    case 12:
        return (hlen > 5) ? @"Yes" : @"No";
    case 13:
        return [self from];
    case 14:
        return [self to];
    case 15:
        return [self flagsMeaning];
    }

    return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
    switch (fieldIndex)
    {
    case 0:
        return val_compare(version, ((IPV4Decode*)obj)->version);
    case 1:
        return val_compare(hlen, ((IPV4Decode*)obj)->hlen);
    case 2:
        return val_compare(tos, ((IPV4Decode*)obj)->tos);
    case 3:
        return val_compare(tlen, ((IPV4Decode*)obj)->tlen);
    case 4:
        return val_compare(ident, ((IPV4Decode*)obj)->ident);
    case 5:
        return val_compare(flags, ((IPV4Decode*)obj)->flags);
    case 6:
        return val_compare(offset, ((IPV4Decode*)obj)->offset);
    case 7:
        return val_compare(ttl, ((IPV4Decode*)obj)->ttl);
    case 8:
        return val_compare(proto, ((IPV4Decode*)obj)->proto);
    case 9:
        return val_compare(sum, ((IPV4Decode*)obj)->sum);
    case 10:
        return mem_compare(&src, &(((IPV4Decode*)obj)->src), sizeof(src));
    case 11:
        return mem_compare(&dst, &(((IPV4Decode*)obj)->dst), sizeof(dst));
    case 12:
        return val_compare(
            (hlen > 5) ? 1 : 0, (((IPV4Decode*)obj)->hlen > 5) ? 1 : 0);
    case 13:
        return [[self resolvFrom] compare:[obj resolvFrom]];
    case 14:
        return [[self resolvTo] compare:[obj resolvTo]];
    case 15:
        return [[self flagsMeaning] compare:[obj flagsMeaning]];
    }

    return NSOrderedSame;
}

/* OutlineView protocol methods */

- (BOOL)expandable
{
    return YES;
}

- (size_t)numberOfChildren
{
    return 12 + ((hlen > 5) ? 1 : 0);
}

- (id)childAtIndex:(int)fieldIndex
{
    OutlineViewItem* ret;
    NSString* str;

    if (fieldIndex == 12)
    { /* options sub-decoder */
        if (optionsDecoder == nil)
        {
            if ((optionsDecoder = [[PPPluginManager sharedPluginManager]
                     pluginWithLongName:@"IPv4 Options"]) == nil)
                return nil;
            [optionsDecoder retain];
        }
        return [optionsDecoder outlineViewItemTreeForData:[self optionsData]];
    }

    ret = [[OutlineViewItem alloc] init];
    [ret addObject:names[fieldIndex][0]];

    switch (fieldIndex)
    {
    case 0:
        str = [[NSString alloc] initWithFormat:@"%u", version];
        [ret addObject:str];
        [str release];
        break;

    case 1:
        str =
            [[NSString alloc] initWithFormat:@"%u (%u Bytes)", hlen, hlen * 4];
        [ret addObject:str];
        [str release];
        break;

    case 2:
        /* needs to be expandable */
        str = [[NSString alloc] initWithFormat:@"0x%.2x", tos];
        [ret addObject:str];
        [str release];
        break;

    case 3:
        /* possibly verify this, i.e inform the user if the length is wrong */
        str = [[NSString alloc] initWithFormat:@"%u Byte(s)", tlen];
        [ret addObject:str];
        [str release];
        break;

    case 4:
        str = [[NSString alloc] initWithFormat:@"%u", ident];
        [ret addObject:str];
        [str release];
        break;

    case 5:
        [ret addObject:[NSString stringWithFormat:@"%@ (%@)",
                                                  binstr(&flags, 3),
                                                  [self flagsMeaning]]];
        [ret addChildWithObjects:[NSString stringWithFormat:@"Reserved"],
                                 [NSString
                                     stringWithFormat:@"%s",
                                                      (flags &
                                                       IPV4DECODE_FLAGS_RES)
                                                          ? "Yes"
                                                          : "No"],
                                 nil];
        [ret addChildWithObjects:[NSString stringWithFormat:@"Don't fragment"],
                                 [NSString
                                     stringWithFormat:@"%s",
                                                      (flags &
                                                       IPV4DECODE_FLAGS_DFRAG)
                                                          ? "Yes"
                                                          : "No"],
                                 nil];
        [ret addChildWithObjects:[NSString stringWithFormat:@"More fragments"],
                                 [NSString
                                     stringWithFormat:@"%s",
                                                      (flags &
                                                       IPV4DECODE_FLAGS_MFRAG)
                                                          ? "Yes"
                                                          : "No"],
                                 nil];
        break;

    case 6:
        str = [[NSString alloc]
            initWithFormat:@"%u (%u Bytes)", offset, offset * 8];
        [ret addObject:str];
        [str release];
        break;

    case 7:
        str = [[NSString alloc]
            initWithFormat:@"%u Hop%s", ttl, (ttl != 1) ? "s" : ""];
        [ret addObject:str];
        [str release];
        break;

    case 8:
        /* needs to be looked up */
        str = [[NSString alloc] initWithFormat:@"0x%.2x", proto];
        [ret addObject:str];
        [str release];
        break;

    case 9:
        if (sum == [self computedChecksum])
            str = [[NSString alloc] initWithFormat:@"0x%.4x (correct)", sum];
        else
            str = [[NSString alloc]
                initWithFormat:@"0x%.4x (incorrect, should be 0x%.4x)",
                               sum,
                               [self computedChecksum]];
        [ret addObject:str];
        [str release];
        break;

    case 10:
        [ret addObject:[self addrFrom]];
        [ret addChildWithCallback:self
                         selector:@selector(resolvCallback:)
                             data:&src];
        break;

    case 11:
        [ret addObject:[self addrTo]];
        [ret addChildWithCallback:self
                         selector:@selector(resolvCallback:)
                             data:&dst];
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

- (void)encodeWithCoder:(NSCoder*)coder
{
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&version];
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&hlen];
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&tos];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&tlen];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&ident];
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&flags];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&offset];
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&ttl];
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&proto];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&sum];
    [coder encodeValueOfObjCType:@encode(struct in_addr) at:&src];
    [coder encodeValueOfObjCType:@encode(struct in_addr) at:&dst];
}

- (id)initWithCoder:(NSCoder*)coder
{
    if ((self = [super init]) != nil)
    {
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&version];
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&hlen];
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&tos];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&tlen];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&ident];
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&flags];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&offset];
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&ttl];
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&proto];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&sum];
        [coder decodeValueOfObjCType:@encode(struct in_addr) at:&src];
        [coder decodeValueOfObjCType:@encode(struct in_addr) at:&dst];
        calced_sum = 0;
        parent = nil;
        optionsDecoder = nil;
    }
    return self;
}

- (void)dealloc
{
    [optionsDecoder release];
    [super dealloc];
}

@end
