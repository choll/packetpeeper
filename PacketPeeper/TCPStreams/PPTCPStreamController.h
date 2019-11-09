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

#ifndef _PPTCPSTREAMCONTROLLER_H_
#define _PPTCPSTREAMCONTROLLER_H_

#include "rb_tree.h"
#import <Foundation/NSObject.h>
#include <netinet/in.h>

#define PPTCPSTREAMS_PORT_HASHMASK 0x7
#define PPTCPSTREAMS_ADDR_HASHMASK 0xF

#define PPTCPSTREAMS_HTABLE_SZ                \
    (((PPTCPSTREAMS_PORT_HASHMASK + 1) * 2) + \
     ((PPTCPSTREAMS_ADDR_HASHMASK + 1) * 2))

@class NSMutableArray;
@class NSIndexSet;
@class TCPDecode;
@class Packet;
@class PPTCPStream;
@class PPTCPStreamReassembler;

@interface PPTCPStreamController : NSObject
{
    struct rb_node* htable[PPTCPSTREAMS_HTABLE_SZ];
    NSMutableArray* streams; /* array of PPTCPStream objects */
    unsigned int sortIndex;
    BOOL dropBadIPChecksums;
    BOOL dropBadTCPChecksums;
    BOOL reverseOrder; /* is the streams array currently in reverse order? */
}

- (void)streamReassemblerRemovedForStream:(PPTCPStream*)stream;
- (PPTCPStreamReassembler*)streamReassemblerForPacket:(Packet*)packet;
- (void)removePacket:(Packet*)packet;
- (PPTCPStream*)tcpStreamForPacket:(Packet*)packet;
- (void)removePacketsAtIndexes:(NSIndexSet*)indexSet
                     forStream:(PPTCPStream*)stream;
- (void)removeStream:(PPTCPStream*)stream;
- (void)removeStreamFromMap:(PPTCPStream*)stream; /* private method */
- (void)removeStreamAtIndex:(NSInteger)index;
- (void)addPacket:(Packet*)packet;
- (void)addPacketArray:(NSArray*)array;
- (void)flush;
- (void)sortStreams:(unsigned int)index;
- (void)setReversePacketOrder:(BOOL)reverse;
- (BOOL)isReverseOrder;
- (NSInteger)indexForStream:(PPTCPStream*)stream;
- (size_t)numberOfStreams;
- (PPTCPStream*)streamAtIndex:(NSInteger)index;

@end

#endif
