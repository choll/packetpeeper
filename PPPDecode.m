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

/*
This is a work in progress-- it hasnt had much effort put into it, simply because
I dont use a PPP connection...
*/

#include "PPPDecode.h"
#include "IPV4Decode.h"
#include "pkt_compare.h"
#import <Foundation/NSArchiver.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>

static NSString* names[][2] = {{@"Address", @"PPP Address"},
                               {@"Control", @"PPP Control"},
                               {@"Protocol", @"PPP Proto"},
                               {@"CRC", @"PPP CRC"}};

#define PPPDECODE_PROTO_IP        0x0021
#define PPPDECODE_PROTO_LINK_CTRL 0xC021
#define PPPDECODE_PROTO_NET_CTRL  0x8021

@implementation PPPDecode

- (id)initWithData:(NSData*)dataVal parent:(id<PPDecoderParent>)parentVal
{
    if (dataVal == nil)
        return nil;

    if ((self = [super init]) != nil)
    {
        /* not enough data is represented by returning nil */
        if ([dataVal length] < PPPDECODE_HDR_MIN)
            goto err;

        addr = *(uint8_t*)[dataVal bytes];
        control = *((uint8_t*)[dataVal bytes] + 1);
        protocol = *(uint16_t*)((uint8_t*)[dataVal bytes] + 2);
        crc = *(uint16_t*)((uint8_t*)[dataVal bytes] + ([dataVal length] - 2));
    }
    return self;

err:
    [self dealloc];
    return nil;
}

- (void)setParent:(id<PPDecoderParent>)parentVal
{
    return;
}

- (size_t)frontSize
{
    return (sizeof(addr) + sizeof(control) + sizeof(protocol));
}

- (size_t)rearSize
{
    return 0; //(sizeof(crc) + 1);
}

- (Class)nextLayer
{
    switch (protocol)
    {
    case PPPDECODE_PROTO_IP:
        return [IPV4Decode class];
        /* NOTREACHED */
    }
    return Nil;
}

+ (NSString*)shortName
{
    return @"PPP";
}

+ (NSString*)longName
{
    return @"PPP";
}

- (NSString*)info
{
    return nil;
}

- (stacklev)level
{
    return SL_DATALINK;
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
        return [NSString stringWithFormat:@"0x%.2x", addr];

    case 1:
        return [NSString stringWithFormat:@"0x%.2x", control];

    case 2:
        return [NSString stringWithFormat:@"0x%.4x", protocol];

    case 3:
        return [NSString stringWithFormat:@"0x%.4x", crc];
    }

    return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
    switch (fieldIndex)
    {
    case 0:
        return val_compare(addr, ((PPPDecode*)obj)->addr);

    case 1:
        return val_compare(control, ((PPPDecode*)obj)->control);

    case 2:
        return val_compare(protocol, ((PPPDecode*)obj)->protocol);

    case 3:
        return val_compare(crc, ((PPPDecode*)obj)->crc);
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
    return 4;
}

- (id)childAtIndex:(int)fieldIndex
{
    OutlineViewItem* ret;
    NSString* str;

    ret = [[OutlineViewItem alloc] init];
    [ret addObject:names[fieldIndex][0]];

    switch (fieldIndex)
    {
    case 0:
        str = [[NSString alloc] initWithFormat:@"0x%.2x", addr];
        [ret addObject:str];
        [str release];
        break;

    case 1:
        str = [[NSString alloc] initWithFormat:@"0x%.2x", control];
        [ret addObject:str];
        [str release];
        break;

    case 2:
        str = [[NSString alloc] initWithFormat:@"0x%.4x", protocol];
        [ret addObject:str];
        [str release];
        break;

    case 3:
        str = [[NSString alloc] initWithFormat:@"0x%.4x", crc];
        [ret addObject:str];
        [str release];
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

- (void)encodeWithCoder:(NSCoder*)coder
{
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&addr];
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&control];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&protocol];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&crc];
}

- (id)initWithCoder:(NSCoder*)coder
{
    if ((self = [super init]) != nil)
    {
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&addr];
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&control];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&protocol];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&crc];
    }
    return self;
}

@end
