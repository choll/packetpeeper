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

#include "PPTCPStreamController.h"
#include "DateFormat.h"
#include "IPV4Decode.h"
#include "NSMutableArrayExtensions.h"
#include "OutlineViewItem.h"
#include "PPTCPStream.h"
#include "PPTCPStreamReassembler.h"
#include "Packet.h"
#include "PacketPeeper.h"
#include "TCPDecode.h"
#include "pkt_compare.h"
#include "stream_compare.h"
#import <Foundation/NSArray.h>
#import <Foundation/NSDate.h>
#import <Foundation/NSString.h>
#import <Foundation/NSUserDefaults.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>

struct endpoint
{
    struct in_addr addr;
    unsigned int port;
};

/* red-black node key */
struct stream_id
{
    struct endpoint alpha;
    struct endpoint beta;
};

static unsigned int stream_hash(const struct stream_id* s_id);
static int stream_comp(const void* key_a, const void* key_b);
static void rb_node_free(struct rb_node* node);
static void rb_key_copy(void* dst, const void* src);

@implementation PPTCPStreamController

- (id)init
{
    unsigned int i;

    if ((self = [super init]) != nil)
    {
        if ((streams = [[NSMutableArray alloc] init]) == nil)
        {
            [super dealloc];
            return nil;
        }

        for (i = 0; i < PPTCPSTREAMS_HTABLE_SZ; ++i)
            htable[i] = NULL;

        sortIndex = 0;
        dropBadIPChecksums = [[NSUserDefaults standardUserDefaults]
            boolForKey:PPTCPSTREAMCONTROLLER_IP_DROP_BAD_CHECKSUMS];
        dropBadTCPChecksums = [[NSUserDefaults standardUserDefaults]
            boolForKey:PPTCPSTREAMCONTROLLER_TCP_DROP_BAD_CHECKSUMS];
        reverseOrder = NO;
    }
    return self;
}

- (void)streamReassemblerRemovedForStream:(PPTCPStream*)stream
{
    [stream setStreamReassembler:nil];
}

- (PPTCPStreamReassembler*)streamReassemblerForPacket:(Packet*)packet
{
    TCPDecode* tcp;
    PPTCPStream* stream;
    PPTCPStreamReassembler* reassembler;

    if ((tcp = [packet decoderForClass:[TCPDecode class]]) == nil)
        return nil;

    if ((stream = [tcp backPointer]) == nil)
        return nil;

    if ((reassembler = [stream streamReassembler]) == nil)
    {
        reassembler = [[PPTCPStreamReassembler alloc] initWithStream:stream
                                                    streamController:self];
        [stream setStreamReassembler:reassembler];
        [reassembler autorelease];
    }

    return reassembler;
}

- (PPTCPStream*)tcpStreamForPacket:(Packet*)packet
{
    TCPDecode* tcp;

    if ((tcp = [packet decoderForClass:[TCPDecode class]]) == nil)
        return nil;

    return [tcp backPointer];
}

- (void)removePacket:(Packet*)packet
{
    TCPDecode* tcp;
    PPTCPStream* stream;

    if ((tcp = [packet decoderForClass:[TCPDecode class]]) == nil)
        return;

    if ((stream = [tcp backPointer]) == nil)
        return;

    [stream removePacket:packet];

    if (![stream isValid])
        [self removeStream:stream];
}

/* this method requires all indexes in the gien indexSet to be correct
   (for the fast-path of deleting the whole stream) */
- (void)removePacketsAtIndexes:(NSIndexSet*)indexSet
                     forStream:(PPTCPStream*)stream
{
    if ([indexSet count] < [stream packetsCount])
    {
        [stream removePacketsAtIndexes:indexSet];
        if (![stream isValid])
            [self removeStream:stream];
    }
    else
        [self removeStream:stream];
}

- (void)removeStream:(PPTCPStream*)stream
{
    if (stream == nil)
        return;

    [streams removeFirstObjectIdenticalTo:stream];
    [[stream streamReassembler] invalidateStream];

    [self removeStreamFromMap:stream];
}

/* private method */
- (void)removeStreamFromMap:(PPTCPStream*)stream
{
    IPV4Decode* ip;
    TCPDecode* tcp;
    struct rb_node* node;
    struct stream_id s_id;
    unsigned int hash_index;

    if (stream == nil)
        return;

    if ((tcp = [stream segmentAtIndex:0]) == nil)
        return;

    if ((ip = [[tcp parent] decoderForClass:[IPV4Decode class]]) == nil)
        return;

    s_id.alpha.addr = [ip in_addrSrc];
    s_id.alpha.port = [tcp srcPort];
    s_id.beta.addr = [ip in_addrDst];
    s_id.beta.port = [tcp dstPort];

    hash_index = stream_hash(&s_id);

    if ((node = rb_search(htable[hash_index], &s_id, stream_comp)) == NULL)
        return;

    htable[hash_index] = rb_node_delete(htable[hash_index], node, rb_key_copy);
    [stream release];
}

- (void)removeStreamAtIndex:(NSInteger)index
{
    PPTCPStream* stream;

    /* transform the index if we are in reverse order */
    if (reverseOrder)
        index = ([streams count] - 1) - index;

    if ((stream = [streams objectAtIndex:index]) == nil)
        return;

    [[stream streamReassembler] invalidateStream];
    [streams removeObjectAtIndex:index];
    [self removeStreamFromMap:stream];
}

- (void)addPacket:(Packet*)packet
{
    struct rb_node* result;
    PPTCPStream* stream;
    IPV4Decode* ip;
    TCPDecode* tcp;
    unsigned int i;
    struct stream_id s_id;

    if (packet == nil)
        return;

    if ((ip = [packet decoderForClass:[IPV4Decode class]]) == nil)
        return;

    if ((tcp = [packet decoderForClass:[TCPDecode class]]) == nil)
        return;

    /* ignore bad flags */
    if (((int)[tcp rstFlag] + (int)[tcp finFlag] + (int)[tcp synFlag]) > 1)
        return;

    /* ignore invalid ip/src combinations */
    if ([tcp srcPort] == [tcp dstPort] &&
        [ip in_addrSrc].s_addr == [ip in_addrDst].s_addr)
        return;

    /*
		Disabled as default because valid packets show up as having invalid checksums in some
		circumstances, probably due to TCP checksum offloading. I think the benefit of
		enabling this (stopping TCP insertion attacks) is not enough to justify breaking
		stream reassembly for these cases.
	*/

    /* ignore corrupt packets */
    if (dropBadIPChecksums && ![ip isChecksumValid])
        return;

    if (dropBadTCPChecksums && ![tcp isChecksumValid])
        return;

    s_id.alpha.addr = [ip in_addrSrc];
    s_id.alpha.port = [tcp srcPort];
    s_id.beta.addr = [ip in_addrDst];
    s_id.beta.port = [tcp dstPort];

    i = stream_hash(&s_id);

    if ((result = rb_search(htable[i], &s_id, stream_comp)) == NULL)
    {
        /* don't bother making a new connection for a stray RST or FIN */
        if ([tcp rstFlag] || [tcp finFlag])
            return;

        /* search failed, create and insert a new red-black node */
        if ((result = malloc(
                 sizeof(struct rb_node) + sizeof(struct stream_id))) == NULL)
            return;

        if ((stream = [[PPTCPStream alloc] init]) == nil)
        {
            free(result);
            return;
        }

        result->data = stream;

        *(struct stream_id*)result->key = s_id;
        htable[i] = rb_insert(htable[i], result, stream_comp);
    }
    else
        stream = result->data;

    if ([stream addPacket:packet])
    {
        /* if we have a valid stream, add it to the streams array */
        if ([stream isValid] && ![stream isDisplayed])
        {
            [stream setDisplayed:YES];
            [streams addObject:stream];
        }
    }
}

- (void)addPacketArray:(NSArray*)packets
{
    unsigned int i;

    for (i = 0; i < [packets count]; ++i)
        [self addPacket:[packets objectAtIndex:i]];
}

- (void)flush
{
    unsigned int i;

    [streams removeAllObjects];

    for (i = 0; i < PPTCPSTREAMS_HTABLE_SZ; ++i)
    {
        rb_free_tree(htable[i], rb_node_free);
        htable[i] = NULL;
    }
}

- (void)sortStreams:(unsigned int)index
{
    sortIndex = index;
    [streams sortUsingFunction:stream_compare context:&sortIndex];
}

- (void)setReversePacketOrder:(BOOL)reverse
{
    reverseOrder = reverse;
}

- (BOOL)isReverseOrder
{
    return reverseOrder;
}

- (NSInteger)indexForStream:(PPTCPStream*)stream
{
    NSInteger upper, lower, current, total;

    if (stream == nil)
        return -1;

    total = [streams count];

    upper = total - 1;
    lower = 0;

    for (;;)
    {
        current = (upper + lower) / 2;

        switch (
            stream_compare([streams objectAtIndex:current], stream, &sortIndex))
        {
        /* current is greater */
        case NSOrderedDescending:
            if (upper == lower)
                return -1;
            upper = current;
            continue;
            /* NOTREACHED */

        /* current is smaller */
        case NSOrderedAscending:
            if (upper == lower)
                return -1;
            lower = current + 1;
            continue;
            /* NOTREACHED */

        case NSOrderedSame:
        default:
            /* stream_compare may be inexact, so compare further */
            for (upper = current; [streams objectAtIndex:upper] != stream;
                 ++upper)
            {
                if (upper == total - 1)
                    return -1;

                if (stream_compare(
                        [streams objectAtIndex:upper + 1],
                        stream,
                        &sortIndex) != NSOrderedSame)
                {
                    for (upper = current - 1;
                         [streams objectAtIndex:upper] != stream;
                         --upper)
                    {
                        if (upper == 0)
                            return -1;
                        if (stream_compare(
                                [streams objectAtIndex:upper - 1],
                                stream,
                                &sortIndex) != NSOrderedSame)
                            return -1;
                    }
                    break;
                }
            }

            if (reverseOrder)
                upper = (total - 1) - upper;

            /* XXX - check upper fits into a signed int? */
            return upper;
            /* NOTREACHED */
        }
    }
    /* NOTREACHED */
}

- (size_t)numberOfStreams
{
    return [streams count];
}

- (PPTCPStream*)streamAtIndex:(NSInteger)index
{
    if (index >= 0 && index < [streams count])
    {
        /* transform the index if we are in reverse order */
        if (reverseOrder)
            index = ([streams count] - 1) - index;
        return [streams objectAtIndex:index];
    }

    return nil;
}

- (void)dealloc
{
    [self flush];
    [streams release];
    [super dealloc];
}

@end

static unsigned int stream_hash(const struct stream_id* s_id)
{
    return (s_id->alpha.addr.s_addr & PPTCPSTREAMS_ADDR_HASHMASK) +
           (s_id->alpha.port & PPTCPSTREAMS_PORT_HASHMASK) +
           (s_id->beta.addr.s_addr & PPTCPSTREAMS_ADDR_HASHMASK) +
           (s_id->beta.port & PPTCPSTREAMS_PORT_HASHMASK);
}

static int stream_comp(const void* key_a, const void* key_b)
{
    struct stream_id *id_a, *id_b;

    id_a = (struct stream_id*)key_a;
    id_b = (struct stream_id*)key_b;

    if (MAX(id_a->alpha.addr.s_addr, id_a->beta.addr.s_addr) <
        MAX(id_b->alpha.addr.s_addr, id_b->beta.addr.s_addr))
    {
        return -1;
    }
    else if (
        MAX(id_a->alpha.addr.s_addr, id_a->beta.addr.s_addr) >
        MAX(id_b->alpha.addr.s_addr, id_b->beta.addr.s_addr))
    {
        return 1;
    }
    else if (
        MIN(id_a->alpha.addr.s_addr, id_a->beta.addr.s_addr) <
        MIN(id_b->alpha.addr.s_addr, id_b->beta.addr.s_addr))
    {
        return -1;
    }
    else if (
        MIN(id_a->alpha.addr.s_addr, id_a->beta.addr.s_addr) >
        MIN(id_b->alpha.addr.s_addr, id_b->beta.addr.s_addr))
    {
        return 1;
    }
    else if (
        MAX(id_a->alpha.port, id_a->beta.port) <
        MAX(id_b->alpha.port, id_b->beta.port))
    {
        return -1;
    }
    else if (
        MAX(id_a->alpha.port, id_a->beta.port) >
        MAX(id_b->alpha.port, id_b->beta.port))
    {
        return 1;
    }
    else if (
        MIN(id_a->alpha.port, id_a->beta.port) <
        MIN(id_b->alpha.port, id_b->beta.port))
    {
        return -1;
    }
    else if (
        MIN(id_a->alpha.port, id_a->beta.port) >
        MIN(id_b->alpha.port, id_b->beta.port))
    {
        return 1;
    }

    return 0;
}

static void rb_node_free(struct rb_node* node)
{
    PPTCPStream* stream;

    stream = node->data;

    [[stream streamReassembler] invalidateStream];
    [stream release];

    free(node);
}

static void rb_key_copy(void* dst, const void* src)
{
    *(struct stream_id*)dst = *(struct stream_id*)src;
}
