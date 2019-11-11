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

#ifndef _ARPDECODE_H_
#define _ARPDECODE_H_

#include "../../PacketPeeper/UI Classes/ColumnIdentifier.h"
#include "Decode.h"
#include "../../PacketPeeper/Describe.h"
#include "../../PacketPeeper/UI Classes/OutlineViewItem.h"
#import <Foundation/NSObject.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdint.h>

#define ARP_FIELD_SZ 8 /* sum of the sizes of the first 5 fields */
#define ARPDECODE_HDR_MIN                           \
    (sizeof(struct arphdr) + (ETHER_ADDR_LEN * 2) + \
     (sizeof(struct in_addr) * 2))

@class NSData;
@class NSString;
@class HostCache;

@interface ARPDecode
    : NSObject <Decode, Describe, NSCoding, OutlineViewItem, ColumnIdentifier>
{
    id<PPDecoderParent> parent;
    uint16_t hardtype; /* hardware addr type, 1 for ethernet */
    uint16_t prottype; /* proto addr type, 0x0800 for IP */
    uint8_t hardsz;    /* hardware addr size, 6 for ether */
    uint8_t protsz;    /* proto addr size, 4 for IP */
    uint16_t op;       /* operation; request, reply, etc */

    /* ethernet and ipv4 only for now, ipv6 will be implemented
	   sometime, but other hardware addresses are unlikely */

    uint8_t ethsender[ETHER_ADDR_LEN];
    struct in_addr ipsender;
    uint8_t ethtarget[ETHER_ADDR_LEN];
    struct in_addr iptarget;
}

- (NSString*)sender;
- (NSString*)target;
- (NSString*)senderEther;
- (NSString*)targetEther;
- (NSString*)senderIP;
- (NSString*)targetIP;
- (NSString*)resolvSender;
- (NSString*)resolvTarget;
- (id<OutlineViewItem>)resolvCallback:(void*)data;
- (NSString*)operationString;
- (id<OutlineViewItem>)operationStringCallback:(void*)data;

@end

@interface RARPDecode : ARPDecode

@end

#endif
