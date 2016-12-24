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
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <errno.h>
#import <Foundation/NSString.h>
#import <Foundation/NSData.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSTimeZone.h>
#import <Foundation/NSDate.h>
#import <Foundation/NSCalendarDate.h>
#import <Foundation/NSUserDefaults.h>
#import <Foundation/NSArchiver.h>
#include "MyDocument.h"
#include "PPPluginManager.h"
#include "ColumnIdentifier.h"
#include "LoopbackDecode.h"
#include "PPRVIDecode.h"
#include "EthernetDecode.h"
#include "PPPDecode.h"
#include "IPV4Decode.h"
#include "demultiplex.h"
#include "pktap.h"
#include "PacketPeeper.h"
#include "Packet.h"

@implementation Packet

- (id)init
{
    return nil;
}

- (id)initWithData:(NSData *)dataVal
    captureLength:(uint32_t)aCaptureLength
    actualLength:(uint32_t)anActualLength
    timestamp:(NSDate *)timestamp
    linkLayer:(Class)linkLayer
{
    if(dataVal == nil || linkLayer == Nil)
        return nil;

    if((self = [super init]) != nil) {
        data = [dataVal retain];
        decoders = nil;
        date = nil;
        document = nil;

        captureLength = aCaptureLength;
        actualLength = anActualLength;

        if((decoders = [[NSMutableArray alloc] init]) == nil)
            goto err;

        if(demultiplex_data(data, decoders, self, linkLayer) == -1)
            goto err;

        date = [timestamp retain];
        pendingDeletion = NO;
        processedPlugins = NO;
    }
    return self;

err:
    [self dealloc];
    return nil;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<Packet: %p, #%lu, %u bytes>", (void*)self, number, captureLength];
}

- (void)setNumber:(unsigned long)aNumber
{
    number = aNumber;
}

- (unsigned long)number
{
    return number;
}

- (HostCache *)hostCache
{
    return [document hostCache];
}

- (MyDocument *)document
{
    return document;
}

- (void)setDocument:(MyDocument *)aDocument
{
    document = aDocument;
}

- (NSArray *)decoders
{
    return decoders;
}

/*
   What is returned here does not include the bpf header, as we do not
   consider that to be a part of the actual packet data, it was not
   sent over the wire, but added by bpf.
   */

- (NSData *)packetData
{
    return data;
}

- (NSData *)dataForDecoder:(id)decoder
{
    size_t offset;

    offset = [self byteOffsetForDecoder:decoder];

    return [NSData dataWithBytesNoCopy:((uint8_t *)[data bytes] + offset)
        length:([data length] - offset)
        freeWhenDone:NO];
}

- (size_t)byteOffsetForDecoder:(id)decoder
{
    unsigned int i;
    size_t nbytes;

    nbytes = 0;

    for(i = 0; i < [decoders count]; ++i) {
        id <Decode> current;

        if((current = [decoders objectAtIndex:i]) == decoder)
            break;

        nbytes += [current frontSize];
    }

    return nbytes;
}

- (uint32_t)captureLength
{
    return captureLength;
}

- (uint32_t)actualLength
{
    return actualLength;
}

- (BOOL)isPendingDeletion
{
    return pendingDeletion;
}

- (void)setPendingDeletion
{
    pendingDeletion = YES;
}

- (int)linkType
{
    Class linkType;

    if([decoders count] < 1)
        return DLT_NULL;

    linkType = [[decoders objectAtIndex:0] class];

    if(linkType == [PPRVIDecode class])
        return DLT_PKTAP;

    if(linkType == [LoopbackDecode class])
        return DLT_NULL;

    if(linkType == [EthernetDecode class])
        return DLT_EN10MB;

    if(linkType == [PPPDecode class])
        return DLT_PPP;

    if(linkType == [IPV4Decode class])
        return DLT_RAW;

    return DLT_NULL;
}

- (NSDate *)date
{
    return date;
}

- (id)decoderForClass:(Class)aClass
{
    unsigned int i;

    if(aClass == Nil)
        return nil;

    for(i = 0; i < [decoders count]; ++i) {
        if([[decoders objectAtIndex:i] isMemberOfClass:aClass])
            return [decoders objectAtIndex:i];
    }

    return nil;
}

/* NSCoding protocol methods */

- (void)encodeWithCoder:(NSCoder *)coder
{
    [coder encodeDataObject:data];
    [coder encodeObject:date];
    [coder encodeObject:decoders];
    [coder encodeValueOfObjCType:@encode(unsigned int) at:&captureLength];
    [coder encodeValueOfObjCType:@encode(unsigned int) at:&actualLength];
    [coder encodeValueOfObjCType:@encode(unsigned int) at:&number];
}

/* Note that only Packet should encode its data object */
- (id)initWithCoder:(NSCoder *)coder
{
    if((self = [super init]) != nil) {
        data = [[coder decodeDataObject] retain];
        date = [[coder decodeObject] retain];
        decoders = [[coder decodeObject] retain];
        [coder decodeValueOfObjCType:@encode(unsigned int) at:&captureLength];
        [coder decodeValueOfObjCType:@encode(unsigned int) at:&actualLength];
        [coder decodeValueOfObjCType:@encode(unsigned int) at:&number];
        [decoders makeObjectsPerformSelector:@selector(setParent:) withObject:self];
        document = nil;
        pendingDeletion = NO;
        processedPlugins = NO;
    }
    return self;
}

- (void)dealloc
{
    [data release];
    [date release];
    [decoders release];
    [super dealloc];
}

@end

