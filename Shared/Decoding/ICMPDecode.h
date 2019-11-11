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

#ifndef _ICMPDECODE_H_
#define _ICMPDECODE_H_

#include "../../PacketPeeper/UI Classes/ColumnIdentifier.h"
#include "Decode.h"
#include "../../PacketPeeper/Describe.h"
#include "../../PacketPeeper/UI Classes/OutlineViewItem.h"
#include "PPDecoderParent.h"
#import <Foundation/NSObject.h>
#include <netinet/in.h>
#include <stdint.h>

#define ICMPDECODE_HDR_MIN ICMP_MINLEN

/* upper union */
#define ICMPDECODE_IDSEQ    0x1
#define ICMPDECODE_GWADDR   0x2
#define ICMPDECODE_PARAMPTR 0x3
/* lower union */
#define ICMPDECODE_IP      0x4
#define ICMPDECODE_UDP     0xC
#define ICMPDECODE_TCP     0x14
#define ICMPDECODE_SUBMASK 0x8
#define ICMPDECODE_TSTAMP  0x10

/* upper/lower refers to the upper/lower unions  */
#define ICMPDECODE_UPPERMASK 0x3
#define ICMPDECODE_LOWERMASK 0x1C

@class NSData;
@class NSString;
@class IPV4Decode;
@class UDPDecode;
@class HostCache;

@interface ICMPDecode : NSObject <
                            Decode,
                            PPDecoderParent,
                            Describe,
                            NSCoding,
                            OutlineViewItem,
                            ColumnIdentifier>
{
    id<PPDecoderParent> parent;
    unsigned char fields; /* stores which fields are present */
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t calced_sum;
    struct
    {
        union {
            struct idseq
            {
                uint16_t ident;
                uint16_t seq;
            } idseq; /* ICMP_ECHOREPLY/ICMP_ECHOREQUEST, ICMP_IREQ/ICMP_IREQREPLY */
            struct in_addr gateway; /* ICMP REDIRECT */
            uint8_t pptr;           /* ICMP_PARAMPROB pointer */
        } upper;
        union {
            uint32_t mask; /* ICMPMASK_REQ/ICMP_MASKREPLY */
            struct
            {
                IPV4Decode* ipdec;
                union {
                    UDPDecode* udpdec;
                    struct minitcp
                    {
                        uint16_t sport;
                        uint16_t dport;
                        uint32_t seq;
                    } tcphdr;
                } payload;
            } ipdata; /* ICMP_UNREACH, ICMP_SOURCEQUENCH, ICMP_REDIRECT, ICMP_TIMXCEED, ICMP_PARAMPROB, */
            struct tstamp
            {
                uint32_t orig;
                uint32_t recv;
                uint32_t trans;
            } tstamp; /* ICMP_TSTAMP/ICMP_TSTAMPREPLY */
        } lower;
    } cont;

    size_t frontSize;
}

- (NSString*)infoType;
- (NSString*)codeString;
- (NSString*)gateway;
- (NSString*)resolvGateway;

/* private methods */
- (id<OutlineViewItem>)resolvCallback:(void*)data;
- (BOOL)isChecksumValid;
- (uint16_t)computedChecksum;
- (void)decodeIPData:(NSData*)dataVal;

@end

#endif
