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

#ifndef _PPTCPSTREAMREASSEMBLER_H_
#define _PPTCPSTREAMREASSEMBLER_H_

#include <sys/types.h>
#include <stdint.h>
#import <Foundation/NSObject.h>

@class NSMutableArray;
@class NSString;
@class NSTimer;
@class NSData;
@class TCPDecode;
@class PPTCPStream;
@class PPTCPStreamController;

struct reassembly_queue {
	NSMutableArray *segments;
	uint32_t first_seq_no;
	uint32_t next_seq_no;
	unsigned int streamIndex;
};

@protocol PPTCPStreamListener <NSObject>

- (void)noteChunksDeleted;
- (void)noteChunksAppended;

@end

@interface PPTCPStreamReassemblerChunk : NSObject
{
	const void *m_data;
	size_t m_length;
	BOOL m_isClient;
}

- (BOOL)isClient;
- (BOOL)isServer;
- (const void *)data;
- (size_t)length;

@end

/*
	So, you have two lists of segments, sorted for you by their start sequence number

	And another list, with them interleaved.

	So, you could look at timestamps

	perhaps, the interleaved list should be used for position, and the client/server lists
	should be used for finding acks.

	so, we keep an ackindex for the client and server, and an index into the main list.


	for deleting segments, perhaps a back ptr wouldht be so bad, eg when 

	unsigned int m_streamIndex;
	unsigned int m_clientStreamIndex;
	unsigned int m_serverStreamIndex;
	uint32_t m_c_seq_no;
	uint32_t m_c_ack_no;
	uint32_t m_s_seq_no;
	uint32_t m_s_ack_no;
*/

@interface PPTCPStreamReassembler : NSObject
{
	NSTimer *m_timer;
	NSMutableArray *m_chunks;
	NSMutableArray *m_listeners;
	PPTCPStreamController *m_streamController;  /* not retained to avoid retain-cycle */
	PPTCPStream *m_stream; /* not retained to avoid retain-cycle */

	unsigned int m_streamIndex; /* data index */
	unsigned int m_clientStreamIndex; /* ack index */
	unsigned int m_serverStreamIndex; /* ack index */
	uint32_t m_c_seq_no;
	uint32_t m_s_seq_no;

	BOOL m_segmentsDeleted;
}

- (id)initWithStream:(PPTCPStream *)stream streamController:(PPTCPStreamController *)streamController;
- (PPTCPStream *)stream;
- (void)addListener:(id <PPTCPStreamListener>)aListener;
- (void)removeListener:(id <PPTCPStreamListener>)aListener;
- (void)reassemble;
- (unsigned int)numberOfChunks;
- (NSData *)chunkDataAt:(unsigned int)chunkIndex;
- (BOOL)chunkIsClient:(unsigned int)chunkIndex;
- (BOOL)chunkIsServer:(unsigned int)chunkIndex;
- (void)reset;
- (void)setTimer; /* private method */
- (void)updateListenersWithTimer:(NSTimer *)aTimer; /* private method */
- (void)invalidateStream;
- (void)noteSegmentsDeleted;
- (void)noteSegmentsAppended;

@end

#endif
