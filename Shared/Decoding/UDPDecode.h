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

#ifndef _UDPDECODE_H_
#define _UDPDECODE_H_

#include "../../PacketPeeper/UI Classes/ColumnIdentifier.h"
#include "Decode.h"
#include "../../PacketPeeper/Describe.h"
#include "../../PacketPeeper/UI Classes/OutlineViewItem.h"
#import <Foundation/NSObject.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdint.h>

#define UDPDECODE_HDR_MIN (sizeof(struct udphdr))

@class NSData;

@interface UDPDecode
    : NSObject <Decode, Describe, NSCoding, OutlineViewItem, ColumnIdentifier>
{
    id<PPDecoderParent> parent;
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t sum;
    uint16_t calced_sum;
}

- (unsigned int)srcPort;
- (unsigned int)dstPort;
- (NSString*)srcPortName;
- (NSString*)dstPortName;
- (BOOL)isChecksumValid;
- (uint16_t)computedChecksum;

@end

#endif
