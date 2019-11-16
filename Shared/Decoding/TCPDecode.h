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

#ifndef _TCPDECODE_H_
#define _TCPDECODE_H_

#include "../../PacketPeeper/Describe.h"
#include "../../PacketPeeper/UI Classes/ColumnIdentifier.h"
#include "../../PacketPeeper/UI Classes/OutlineViewItem.h"
#include "Decode.h"
#import <Foundation/NSObject.h>
#include <stdint.h>

#define TCPDECODE_HDR_MIN (sizeof(struct tcphdr))

@class NSData;
@class NSDate;
@class NSString;
@class Packet;
@class IPV4Decode;

@interface TCPDecode
    : NSObject <Decode, Describe, NSCoding, OutlineViewItem, ColumnIdentifier>
{
    id<PPDecoderParent> parent;
    void* back_ptr;
    uint32_t seq_no;
    uint32_t ack_no;
    uint32_t size;
    uint16_t sport;
    uint16_t dport;
    uint16_t win_sz;
    uint16_t sum;
    uint16_t urg_ptr;
    uint16_t calced_sum;
    uint8_t hlen;
    uint8_t flags;
    BOOL inOrder;
}

- (NSString*)flagsStr;
- (NSString*)srcPortName;
- (NSString*)dstPortName;
- (BOOL)isChecksumValid;
- (uint16_t)computedChecksum;
- (uint32_t)seqNo;
- (uint32_t)ackNo;
- (unsigned int)srcPort;
- (unsigned int)dstPort;
- (uint8_t)flags;
- (BOOL)eceFlag;
- (BOOL)cwrFlag;
- (BOOL)urgFlag;
- (BOOL)ackFlag;
- (BOOL)pushFlag;
- (BOOL)rstFlag;
- (BOOL)synFlag;
- (BOOL)finFlag;
- (uint32_t)size;
- (NSData*)payload;
- (IPV4Decode*)ip;
- (id<PPDecoderParent>)parent;
- (NSDate*)date;
- (BOOL)isInOrder;
- (void)setInOrder:(BOOL)flag;
- (void)setBackPointer:(void*)ptr;
- (void*)backPointer;
- (BOOL)isEqualToSegment:(TCPDecode*)segment;

@end

BOOL tcpdecode_rstFlag(TCPDecode* segment);
BOOL tcpdecode_ackFlag(TCPDecode* segment);
BOOL tcpdecode_synFlag(TCPDecode* segment);
BOOL tcpdecode_finFlag(TCPDecode* segment);

#endif /* _TCPDECODE_H_ */
