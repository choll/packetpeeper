/*
 * Packet Peeper
 * Copyright 2006, 2007, Chris E. Holloway
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
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#import <Foundation/NSTimer.h>
#include "IPV4Decode.h"
#include "TCPDecode.h"
#include "PPTCPStreamController.h"
#include "PPTCPStream.h"
#include "PacketPeeper.h"
#include "PPTCPStreamReassembler.h"

@implementation PPTCPStreamReassemblerChunk

- (id)initWithData:(const void *)data length:(size_t)length isClient:(BOOL)isClient
{
	if((self = [super init]) != nil) {
		m_data = data;
		m_length = length;
		m_isClient = isClient;
	}
	return self;
}

- (BOOL)isClient
{
	return m_isClient;
}

- (BOOL)isServer
{
	return !m_isClient;
}

- (const void *)data
{
	return m_data;
}

- (size_t)length
{
	return m_length;
}

@end

@implementation PPTCPStreamReassembler

- (id)initWithStream:(PPTCPStream *)stream streamController:(PPTCPStreamController *)streamController
{
	if((self = [super init]) != nil) {
		m_timer = nil;
		m_chunks = nil;
		m_listeners = nil;

		if((m_chunks = [[NSMutableArray alloc] init]) == nil)
			goto err;

		if((m_listeners = [[NSMutableArray alloc] init]) == nil)
			goto err;

		m_streamController = streamController;
		m_stream = stream;

		m_streamIndex = 0;
		m_clientStreamIndex = 0;
		m_serverStreamIndex = 0;

		m_segmentsDeleted = NO;

		m_c_seq_no = [[m_stream clientSegmentAtIndex:0] seqNo];
		m_s_seq_no = [[m_stream serverSegmentAtIndex:0] seqNo];
	}
	return self;

	err:
		[m_chunks release];
		[m_listeners release];
		[super dealloc];
		return nil;
}

- (PPTCPStream *)stream
{
	return m_stream;
}

- (void)addListener:(id <PPTCPStreamListener>)listener
{
	if(listener != nil && ![m_listeners containsObject:listener]) {
		[m_listeners addObject:listener];
		[listener release]; /* remove the retain done by the listeners array */
		// XXX NEED TO REVISE THIS, PROBABLY BETTER THAT LISTENERS DON'T RETAIN US
	}
}

- (void)removeListener:(id <PPTCPStreamListener>)listener
{
	if(listener != nil) {
		/* balance the release to be done by the listeners array */
		[listener retain];
		[m_listeners removeObject:listener];
		if([m_listeners count] == 0 && m_stream != nil)
			[m_streamController streamReassemblerRemovedForStream:m_stream];
	}
}

- (void)reassemble
{
	PPTCPStreamReassemblerChunk *chunk;
	unsigned int i;
	BOOL checkClient;
	BOOL checkServer;

	checkClient = YES;
	checkServer = YES;

	for(i = m_streamIndex; i < [m_stream packetsCount] && (checkClient || checkServer); ++i) {
		TCPDecode *segment;
		size_t nbytes;
		size_t offset;

		segment = [m_stream segmentAtIndex:i];

		if([segment size] < 1)
			continue;

		if([m_stream segmentIsClient:segment]) {
			if(checkClient) {
				if(TCP_SEQ_LE(TCPDECODE_SEQNO_NEXT(segment), m_c_seq_no))
					continue; /* no new data */

				/* find a segment which ACKs the data in segmentAtIndex:i */
				nbytes = 0;
				offset = TCP_SEQ_GT(m_c_seq_no, [segment seqNo]) ? TCP_SEQNO_DIFF(m_c_seq_no, [segment seqNo]) : 0;
				for(; m_serverStreamIndex < [m_stream serverSegmentsCount]; ++m_serverStreamIndex) {
					if(![[m_stream serverSegmentAtIndex:m_serverStreamIndex] ackFlag])
						continue;
					if(TCP_SEQ_GE([[m_stream serverSegmentAtIndex:m_serverStreamIndex] ackNo], TCPDECODE_SEQNO_NEXT(segment))) {
						/* full ack */
						nbytes = SIZE_MAX;
						m_c_seq_no = TCPDECODE_SEQNO_NEXT(segment);
						break;
					} else if(TCP_SEQ_GT([[m_stream serverSegmentAtIndex:m_serverStreamIndex] ackNo], m_c_seq_no)) {
						/* partial ack */
						nbytes = TCP_SEQNO_DIFF([[m_stream serverSegmentAtIndex:m_serverStreamIndex] ackNo], m_c_seq_no);
						m_c_seq_no += nbytes;
					}

				}

				if(nbytes < 1) {
					checkClient = NO;
					continue;
				}

				/* this should *always* be true, but it doesn't hurt to check... */
				if(offset < [[segment payload] length]) {
					chunk = [[PPTCPStreamReassemblerChunk alloc] initWithData:(uint8_t *)[[segment payload] bytes] + offset
																length:MIN(nbytes, [[segment payload] length] - offset)
																isClient:YES];
					[m_chunks addObject:chunk];
					[chunk release];
				}

				if(nbytes != SIZE_MAX)
					break; /* segment was only partially acked */
			}
		} else { /* server segment */
			if(checkServer) {
				if(TCP_SEQ_LE(TCPDECODE_SEQNO_NEXT(segment), m_s_seq_no))
					continue; /* no new data */

				/* find a segment which ACKs the data in segmentAtIndex:i */
				nbytes = 0;
				offset = TCP_SEQ_GT(m_s_seq_no, [segment seqNo]) ? TCP_SEQNO_DIFF(m_s_seq_no, [segment seqNo]) : 0;
				for(; m_clientStreamIndex < [m_stream clientSegmentsCount]; ++m_clientStreamIndex) {
					if(![[m_stream clientSegmentAtIndex:m_clientStreamIndex] ackFlag])
						continue;
					if(TCP_SEQ_GE([[m_stream clientSegmentAtIndex:m_clientStreamIndex] ackNo], TCPDECODE_SEQNO_NEXT(segment))) {
						/* full ack */
						nbytes = SIZE_MAX;
						m_s_seq_no = TCPDECODE_SEQNO_NEXT(segment);
						break;
					} else if(TCP_SEQ_GT([[m_stream clientSegmentAtIndex:m_clientStreamIndex] ackNo], m_s_seq_no)) {
						/* partial ack */
						nbytes = TCP_SEQNO_DIFF([[m_stream clientSegmentAtIndex:m_clientStreamIndex] ackNo], m_s_seq_no);
						m_s_seq_no += nbytes;
					}
				}

				if(nbytes < 1) {
					checkServer = NO;
					continue;
				}

				/* this should *always* be true, but it doesn't hurt to check... */
				if(offset < [[segment payload] length]) {
					chunk = [[PPTCPStreamReassemblerChunk alloc] initWithData:(uint8_t *)[[segment payload] bytes] + offset
																length:MIN(nbytes, [[segment payload] length] - offset)
																isClient:NO];
					[m_chunks addObject:chunk];
					[chunk release];
				}

				if(nbytes != SIZE_MAX)
					break; /* segment was only partially acked */
			}
		}
	}
	m_streamIndex = i;
}

- (unsigned int)numberOfChunks
{
	return [m_chunks count];
}

- (NSData *)chunkDataAt:(unsigned int)chunkIndex
{
	PPTCPStreamReassemblerChunk *chunk;
	
	chunk = [m_chunks objectAtIndex:chunkIndex];

	return [NSData dataWithBytesNoCopy:(void *)[chunk data] length:[chunk length] freeWhenDone:NO];
}

- (BOOL)chunkIsClient:(unsigned int)chunkIndex
{
	return [[m_chunks objectAtIndex:chunkIndex] isClient];
}

- (BOOL)chunkIsServer:(unsigned int)chunkIndex
{
	return [[m_chunks objectAtIndex:chunkIndex] isServer];
}

- (void)reset
{
	[m_chunks removeAllObjects];
	[m_timer release];
	m_timer = nil;

	m_streamIndex = 0;
	m_clientStreamIndex = 0;
	m_serverStreamIndex = 0;

	m_c_seq_no = [[m_stream clientSegmentAtIndex:0] seqNo];
	m_s_seq_no = [[m_stream serverSegmentAtIndex:0] seqNo];
}

- (void)setTimer
{
	if(m_timer == nil || ![m_timer isValid]) {
		[m_timer release];
		m_timer = [[NSTimer scheduledTimerWithTimeInterval:DEFAULT_UI_UPDATE_FREQUENCY target:self selector:@selector(updateListenersWithTimer:) userInfo:nil repeats:NO] retain];
	}
}

- (void)updateListenersWithTimer:(NSTimer *)aTimer
{
	if(m_stream == nil)
		return;

	[self reassemble];

	if(m_segmentsDeleted) {
		m_segmentsDeleted = NO;
		[m_listeners makeObjectsPerformSelector:@selector(noteChunksDeleted)];
	} else
		[m_listeners makeObjectsPerformSelector:@selector(noteChunksAppended)];
}

- (void)invalidateStream
{
	m_stream = nil;
	[m_listeners makeObjectsPerformSelector:@selector(close)];
	// XXX this should be part of the protocol, method should then call close itself.
	// also, we should send self when we do notifications like chunks deleted or appended,
	// might want an object which listens to multiple streams.
	/*
		chunks deleted/appended should send some chunk identification and sender info.
	*/
}

- (void)noteSegmentsDeleted
{
	if(m_stream == nil)
		return;

	m_segmentsDeleted = YES;

	[self reset];
	[self setTimer];
}

- (void)noteSegmentsAppended
{
	if(m_stream == nil)
		return;

	[self setTimer];
}

- (void)dealloc
{
	[self reset];
	[m_chunks release];
	/* balance the release to be done by the m_listeners array */
	[m_listeners makeObjectsPerformSelector:@selector(retain)];
	[m_listeners release];
	[super dealloc];
}

@end
