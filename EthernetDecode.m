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
#include <net/ethernet.h>
#include <netinet/in.h>
#include <string.h>
#import <Foundation/NSData.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArchiver.h>
#include "ARPDecode.h"
#include "IPV4Decode.h"
#include "IPV6Decode.h"
#include "OUICache.h"
#include "ColumnIdentifier.h"
#include "strfuncs.h"
#include "pkt_compare.h"
#include "EthernetDecode.h"

static NSString *names[][2] =
    {{@"Destination Address", @"Ether Dst"},
    {@"Source Address", @"Ether Src"},
    {@"Protocol Type", @"Ether Proto"},
    {@"Destination Address Manufacturer", @"Ether Dst Manuf"},
    {@"Source Address Manufacturer", @"Ether Src Manuf"}};

@implementation EthernetDecode

- (id)initWithData:(NSData *)dataVal parent:(id <PPDecoderParent>)parentVal
{
    struct ether_header *hdr;

    if(dataVal == nil)
        return nil;

    if((self = [super init]) != nil) {
        if([dataVal length] < ETHERNETDECODE_HDR_MIN)
            goto err;

        hdr = (struct ether_header *)[dataVal bytes];

        (void)memcpy(src, hdr->ether_shost, sizeof(src));
        (void)memcpy(dst, hdr->ether_dhost, sizeof(dst));
        type = ntohs(hdr->ether_type);
    }
    return self;

err:
    [self dealloc];
    return nil;
}

- (uint8_t *)dst
{
    return dst;
}

- (uint8_t *)src
{
    return src;
}

- (uint16_t)type
{
    return type;
}

- (void)setParent:(id <PPDecoderParent>)parentVal
{
    return;
}

- (unsigned int)frontSize
{
    return ETHER_HDR_LEN;
}

- (unsigned int)rearSize
{
    return 0;
}

- (Class)nextLayer
{
    switch(type) {
        case ETHERTYPE_IP:
            return [IPV4Decode class];
            /* NOTREACHED */

        case ETHERTYPE_IPV6:
            return [IPV6Decode class];
            /* NOTREACHED */

        case ETHERTYPE_ARP:
            return [ARPDecode class];
            /* NOTREACHED */

        case ETHERTYPE_REVARP:
            return [RARPDecode class];
            /* NOTREACHED */
    }
    return Nil;
}

+ (NSString *)shortName
{
    return @"Ethernet";
}

+ (NSString *)longName
{
    return @"Ethernet";
}

- (NSString *)info
{
    return [NSString stringWithFormat:@"%@ to %@", etherstr(dst, sizeof(dst)), etherstr(src, sizeof(src))];
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
        case 0: /* destination addr */
            return etherstr(dst, sizeof(dst));
        case 1: /* source addr */
            return etherstr(src, sizeof(src));
        case 2: /* type */
            return [NSString stringWithFormat:@"0x%.4x", type];
        case 3: /* dst oui */
            return [[OUICache sharedOUICache] manufacturerForEthernetAddress:dst];
        case 4: /* src oui */
            return [[OUICache sharedOUICache] manufacturerForEthernetAddress:src];
    }

    return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
    switch(fieldIndex) {
        case 0: /* destination addr */
            return mem_compare(dst, ((EthernetDecode *)obj)->dst, sizeof(dst));
        case 1: /* source addr */
            return mem_compare(src, ((EthernetDecode *)obj)->src, sizeof(src));
        case 2: /* type */
            return val_compare(type, ((EthernetDecode *)obj)->type);
        case 3: /* dst oui */
            return [[[OUICache sharedOUICache] manufacturerForEthernetAddress:dst] compare:[[OUICache sharedOUICache] manufacturerForEthernetAddress:((EthernetDecode *)obj)->dst]];
        case 4: /* src oui */
            return [[[OUICache sharedOUICache] manufacturerForEthernetAddress:src] compare:[[OUICache sharedOUICache] manufacturerForEthernetAddress:((EthernetDecode *)obj)->src]];
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
    return 3;
}

- (id)childAtIndex:(int)fieldIndex
{
    OutlineViewItem *ret;
    NSString *str;

    ret = [[OutlineViewItem alloc] init];
    [ret addObject:names[fieldIndex][0]];

    switch(fieldIndex) {
        case 0:
            [ret addObject:etherstr(dst, sizeof(dst))];
            if((str = [[OUICache sharedOUICache] manufacturerForEthernetAddress:dst]) == nil)
                str = @"Lookup failed";
            [ret addChildWithObjects:names[3][0], str, nil];
            break;

        case 1:
            [ret addObject:etherstr(src, sizeof(src))];
            if((str = [[OUICache sharedOUICache] manufacturerForEthernetAddress:src]) == nil)
                str = @"Lookup failed";
            [ret addChildWithObjects:names[4][0], str, nil];
            break;

        case 2:
            str = [[NSString alloc] initWithFormat:@"0x%.4x", type];
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

- (void)encodeWithCoder:(NSCoder *)coder
{
    [coder encodeArrayOfObjCType:@encode(unsigned char) count:sizeof(dst) at:dst];
    [coder encodeArrayOfObjCType:@encode(unsigned char) count:sizeof(src) at:src];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&type];
}

- (id)initWithCoder:(NSCoder *)coder
{
    if((self = [super init]) != nil) {
        [coder decodeArrayOfObjCType:@encode(unsigned char) count:sizeof(dst) at:dst];
        [coder decodeArrayOfObjCType:@encode(unsigned char) count:sizeof(src) at:src];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&type];
    }
    return self;
}

@end

