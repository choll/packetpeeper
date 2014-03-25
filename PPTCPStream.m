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

#include <netinet/tcp.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSDate.h>
#import <Foundation/NSString.h>
#import <Foundation/NSIndexSet.h>
#include "Packet.h"
#include "TCPDecode.h"
#include "IPV4Decode.h"
#include "strfuncs.h"
#include "PPTCPStreamReassembler.h"
#include "NSMutableArrayExtensions.h"
#include "stream_compare.h"
#include "PPTCPStream.h"

static SEL add_pkt_dispatch_table[STATUS_NELEMS];

@implementation PPTCPStream

- (id)init
{
	if((self = [super init]) != nil) {
		m_streamReassembler = nil;

		m_packets = [[NSMutableArray alloc] init];

		m_serverSegments = [[NSMutableArray alloc] init];
		m_clientSegments = [[NSMutableArray alloc] init];

		m_clientQueue = [[NSMutableArray alloc] init];
		m_serverQueue = [[NSMutableArray alloc] init];

		m_client_nbytes = 0;
		m_server_nbytes = 0;

		m_isValid = NO;
		m_isDisplayed = NO;

		[self setStatus:STATUS_UNINITIALISED];

		add_pkt_dispatch_table[STATUS_UNINITIALISED] = @selector(addPacketUninitialised:);
		add_pkt_dispatch_table[STATUS_CLOSED] = @selector(addPacketClosed:);
		add_pkt_dispatch_table[STATUS_SYN_SENT] = @selector(addPacketSynSent:);
		add_pkt_dispatch_table[STATUS_SIMULTANEOUS_OPEN] = @selector(addPacketSimultaneousOpen:);
		add_pkt_dispatch_table[STATUS_SIMULTANEOUS_SYN_ACK_WAIT_CLIENT] = @selector(addPacketSimultaneousSynAckWaitClient:);
		add_pkt_dispatch_table[STATUS_SIMULTANEOUS_SYN_ACK_WAIT_SERVER] = @selector(addPacketSimultaneousSynAckWaitServer:);
		add_pkt_dispatch_table[STATUS_SIMULTANEOUS_ACK_WAIT_CLIENT] = @selector(addPacketSimultaneousAckWaitClient:);
		add_pkt_dispatch_table[STATUS_SIMULTANEOUS_ACK_WAIT_SERVER] = @selector(addPacketSimultaneousAckWaitServer:);
		add_pkt_dispatch_table[STATUS_SYN_ACK_RECV] = @selector(addPacketSynAckRecv:);
		add_pkt_dispatch_table[STATUS_ESTABLISHED] = @selector(addPacketEstablished:);
		add_pkt_dispatch_table[STATUS_FIN_WAIT_CLIENT_1] = @selector(addPacketFinWaitClient1:);
		add_pkt_dispatch_table[STATUS_FIN_WAIT_SERVER_1] = @selector(addPacketFinWaitServer1:);
		add_pkt_dispatch_table[STATUS_FIN_WAIT_CLIENT_2] = @selector(addPacketFinWaitClient2:);
		add_pkt_dispatch_table[STATUS_FIN_WAIT_SERVER_2] = @selector(addPacketFinWaitServer2:);
		add_pkt_dispatch_table[STATUS_SIMULTANEOUS_CLOSE] = @selector(addSimultaneousClose:);
		add_pkt_dispatch_table[STATUS_ACK_WAIT_CLIENT] = @selector(addPacketAckWaitClient:);
		add_pkt_dispatch_table[STATUS_ACK_WAIT_SERVER] = @selector(addPacketAckWaitServer:);
		add_pkt_dispatch_table[STATUS_TIME_WAIT] = @selector(addPacketTimeWait:);
	}
	return self;
}

- (NSString *)description
{
	return [NSString stringWithFormat:@"<PPTCPStream: %p, %@, valid: %s, client<queue: %lu, segments: %lu> server<queue: %lu, segments: %lu>",
			self, [self status], m_isValid ? "yes" : "no", (unsigned long)[m_clientQueue count], (unsigned long)[m_clientSegments count],
			(unsigned long)[m_serverQueue count], (unsigned long)[m_serverSegments count]];
}

- (void)setStreamReassembler:(PPTCPStreamReassembler *)streamReassembler
{
	[streamReassembler retain];
	[m_streamReassembler release];
	m_streamReassembler = streamReassembler;
}

- (PPTCPStreamReassembler *)streamReassembler
{
	return m_streamReassembler;
}

- (void)setStatus:(enum stream_status)status
{
	m_status = status;
	m_isValid = ((m_isValid || m_status == STATUS_ESTABLISHED) ? YES : NO);
	if(m_status == STATUS_CLOSED || m_status == STATUS_TIME_WAIT) {
		[m_clientQueue release];
		[m_serverQueue release];
		m_clientQueue = nil;
		m_serverQueue = nil;
	}
}

- (void)setClientSegment:(TCPDecode *)segment
{
	m_client_sport = [segment srcPort];
	m_client_dport = [segment dstPort];
	m_client_srcip = [[segment ip] in_addrSrc];
	m_client_dstip = [[segment ip] in_addrDst];
}

- (BOOL)segmentIsClient:(TCPDecode *)segment
{
	return ([segment srcPort] == m_client_sport && [[segment ip] in_addrSrc].s_addr == m_client_srcip.s_addr);
}

- (BOOL)segmentIsServer:(TCPDecode *)segment
{
	return ![self segmentIsClient:segment];
}

- (void)incrementServerSegmentBytes:(TCPDecode *)segment
{
	uint32_t cur_seq;
	uint32_t prev_seq;
	uint32_t increment;
	TCPDecode *last;

	if([segment size] < 1)
		return;

	if([m_serverSegments count] < 1) {
		m_server_nbytes = [segment size];
		return;
	}

	last = [m_serverSegments lastObject];
	prev_seq = TCPDECODE_SEQNO_NEXT(last);
	cur_seq = TCPDECODE_SEQNO_NEXT(segment);

	if(!TCP_SEQ_GT(cur_seq, prev_seq))
		return;

	increment = TCP_SEQNO_DIFF(cur_seq, prev_seq);

	if([segment synFlag] || [segment finFlag]) {
		if(increment < 1)
			return;
		--increment;
	}

	m_server_nbytes += increment;
}
 
- (void)incrementClientSegmentBytes:(TCPDecode *)segment
{
	uint32_t cur_seq;
	uint32_t prev_seq;
	uint32_t increment;
	TCPDecode *last;

	if([segment size] < 1)
		return;

	if([m_clientSegments count] < 1) {
		m_client_nbytes = [segment size];
		return;
	}

	last = [m_clientSegments lastObject];
	prev_seq = TCPDECODE_SEQNO_NEXT(last);
	cur_seq = TCPDECODE_SEQNO_NEXT(segment);

	if(!TCP_SEQ_GT(cur_seq, prev_seq))
		return;

	increment = TCP_SEQNO_DIFF(cur_seq, prev_seq);

	if([segment synFlag] || [segment finFlag]) {
		if(increment < 1)
			return;
		--increment;
	}

	m_client_nbytes += increment;
}

- (BOOL)addPacket:(Packet *)packet
{
	TCPDecode *segment;
	enum segment_action action;

	/* addPacket methods work from the perspective of the client */

	/* incoming packet is too new to be part of this stream, discard */
	if([m_packets count] > 0 && [[packet date] timeIntervalSinceDate:[[m_packets lastObject] date]] > PPTCPSTREAM_MSL * 2)
		return NO;

	if((segment = [packet decoderForClass:[TCPDecode class]]) == nil)
		return NO;

	action = (intptr_t)[self performSelector:add_pkt_dispatch_table[m_status] withObject:segment];

	if(action == SEGMENT_DISCARD)
		return YES;

	if(m_status == STATUS_CLOSED && action == SEGMENT_REJECT)
		return NO;

	if(action == SEGMENT_REJECT) {
		/* out of order */
		if([self segmentIsClient:segment]) {
			/* we already know that TCP_SEQ_GT([segment seqNo], m_c_seq_no) due to checks in addPacketEstablished: */
			if(TCP_SEQNO_DIFF([segment seqNo], m_c_seq_no) > PPTCPSTREAM_REASSEMBLY_WINDOW_SZ)
				return YES; /* discard */
			[self addSegment:segment toQueue:m_clientQueue];
		} else { /* server segment */
			/* we already know that TCP_SEQ_GT([segment seqNo], m_s_seq_no) due to checks in addPacketEstablished: */
			if(TCP_SEQNO_DIFF([segment seqNo], m_s_seq_no) > PPTCPSTREAM_REASSEMBLY_WINDOW_SZ)
				return YES; /* discard */
			[self addSegment:segment toQueue:m_serverQueue];
		}
	} else { /* action == SEGMENT_ACCEPT */
		[segment setInOrder:YES];

		if([segment rstFlag]) {
			/* XXX we should not leave TIME_WAIT due to RST, according to RFC 1337 */
			if([self segmentIsClient:segment]) {
				if([segment seqNo] == m_c_seq_no)
					[self setStatus:STATUS_CLOSED];
			} else { /* server segment */
				if([segment seqNo] == m_s_seq_no)
					[self setStatus:STATUS_CLOSED];
			}
		}

		while([m_clientQueue count] > 0) {
			action = (intptr_t)[self performSelector:add_pkt_dispatch_table[m_status] withObject:[m_clientQueue objectAtIndex:0]];
			if(action != SEGMENT_ACCEPT)
				break;
			[m_clientQueue removeObjectAtIndex:0];
		}
		while([m_serverQueue count] > 0) {
			action = (intptr_t)[self performSelector:add_pkt_dispatch_table[m_status] withObject:[m_serverQueue objectAtIndex:0]];
			if(action != SEGMENT_ACCEPT)
				break;
			[m_serverQueue removeObjectAtIndex:0];
		}
	}

	if(m_streamReassembler != nil)
		[m_streamReassembler noteSegmentsAppended];

	return YES;
}

- (enum segment_action)addPacketUninitialised:(TCPDecode *)segment
{
	if([segment synFlag]) {
		[self setClientSegment:segment];
		[self addClientSegment:segment];
		[self setStatus:STATUS_SYN_SENT];
	} else if(![segment rstFlag] && ![segment finFlag]) {
		[self setClientSegment:segment];
		[self addClientSegment:segment];
		/* try to handle already open streams, next server segment
		   will be accepted without a sequence number check (as we
		   could only check using [segment ackNo], which isn't 100%
		   reliable */
		[self setStatus:STATUS_ESTABLISHED];
	}

	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketClosed:(TCPDecode *)segment
{
	/* this check isnt strictly needed, but without it we'd go
	   to the uninitialised state in a new stream object */
	if([segment rstFlag] || [segment finFlag])
		return SEGMENT_ACCEPT;

	return SEGMENT_REJECT;
}

- (enum segment_action)addPacketSynSent:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment synFlag]) /* repeated syn */
			[self addClientSegment:segment];
	} else { /* server segment */
		if([segment synFlag] && [segment ackFlag]) { /* no isn available to verify */
			if([segment ackNo] == m_c_seq_no) { /* syn/ack reply */
				[self addServerSegment:segment];
				[self setStatus:STATUS_SYN_ACK_RECV];
			}
		} else if([segment synFlag]) {
			/* simultaneous open */
			[self addServerSegment:segment];
			[self setStatus:STATUS_SIMULTANEOUS_OPEN];
		}

		/* At some point I will add support for handing weird but technically valid
		 * handshakes, e.g. things like breaking the syn/ack reply into multiple
		 * packets. For now though, I don't care about this, Packet Peeper is not
		 * supposed to be an IDS, and there are easier ways to fool it.
		 */
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketSimultaneousOpen:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment synFlag] && [segment ackFlag] && [segment ackNo] == m_s_seq_no) {
			[self addClientSegment:segment];
			[self setStatus:STATUS_SIMULTANEOUS_SYN_ACK_WAIT_SERVER];
		}
	} else { /* server segment */
		if([segment synFlag] && [segment ackFlag] && [segment ackNo] == m_c_seq_no) {
			[self addClientSegment:segment];
			[self setStatus:STATUS_SIMULTANEOUS_SYN_ACK_WAIT_CLIENT];
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketSimultaneousSynAckWaitClient:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment synFlag] && [segment ackFlag] && [segment ackNo] == m_s_seq_no) {
			[self addClientSegment:segment];
			[self setStatus:STATUS_SIMULTANEOUS_SYN_ACK_WAIT_SERVER_2];
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketSimultaneousSynAckWaitServer:(TCPDecode *)segment
{
	if([self segmentIsServer:segment]) {
		if([segment synFlag] && [segment ackFlag] && [segment ackNo] == m_c_seq_no) {
			[self addServerSegment:segment];
			[self setStatus:STATUS_SIMULTANEOUS_SYN_ACK_WAIT_CLIENT_2];
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketSimultaneousSynAckWaitClient2:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment synFlag] && [segment ackFlag] && [segment ackNo] == m_s_seq_no) {
			[self addClientSegment:segment];
			[self setStatus:STATUS_ESTABLISHED];
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketSimultaneousSynAckWaitServer2:(TCPDecode *)segment
{
	if([self segmentIsServer:segment]) {
		if([segment synFlag] && [segment ackFlag] && [segment ackNo] == m_s_seq_no) {
			[self addServerSegment:segment];
			[self setStatus:STATUS_ESTABLISHED];
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketSynAckRecv:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment seqNo] == m_c_seq_no && [segment ackFlag] && [segment ackNo] == m_s_seq_no) { /* ack reply */
			[self addClientSegment:segment];
			[self setStatus:STATUS_ESTABLISHED];
		}
	} else { /* server segment */
		if([segment synFlag] && [segment ackFlag]) { /* no isn to verify */
			if([segment ackNo] == m_c_seq_no) /* repeated syn/ack reply */
				[self addServerSegment:segment];
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketEstablished:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment seqNo] == m_c_seq_no) {
			[self addClientSegment:segment];
			if([segment finFlag])
				[self setStatus:STATUS_FIN_WAIT_SERVER_1];
		} else {
			/* out of order */
			if(TCP_SEQ_LT([segment seqNo], m_c_seq_no)) {
				/* max segment size acts as a 'window size' here */
				if(TCPDECODE_SEQNO_NEXT(segment) > m_c_seq_no)
					[self addClientSegment:segment];
				/* otherwise discard the segment; I suppose its possible that this could have a
				   higher ack than seen before, but I would expect a TCP/IP stack to just throw
				   something with a bad sequence number away */
				return SEGMENT_DISCARD;
			}
			return SEGMENT_REJECT;
		}
	} else { /* server segment */
		if([m_serverSegments count] < 1) {
			/* we're in the established state without seeing a 3-way handshake,
			   so blindly accept whatever sever sequence number we see first */
			m_s_seq_no = [segment seqNo];
		}

		if([segment seqNo] == m_s_seq_no) {
			[self addServerSegment:segment];
			if([segment finFlag])
				[self setStatus:STATUS_FIN_WAIT_CLIENT_1];
		} else {
			/* out of order */
			if(TCP_SEQ_LT([segment seqNo], m_s_seq_no)) {
				/* max segment size acts as a 'window size' here */
				if(TCPDECODE_SEQNO_NEXT(segment) > m_s_seq_no)
					[self addServerSegment:segment];
				/* otherwise discard the segment */
				return SEGMENT_DISCARD;
			}
			return SEGMENT_REJECT;
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketFinWaitClient1:(TCPDecode *)segment
{
	/* server sent fin, waiting for client fin */
	if([self segmentIsClient:segment]) {
		if([segment seqNo] == m_c_seq_no && [segment ackFlag] && TCP_SEQ_GE([segment ackNo], m_s_seq_no)) {
			if([segment finFlag]) { /* fin,ack */
				[self addClientSegment:segment];
				[self setStatus:STATUS_ACK_WAIT_SERVER];
			} else { /* ack only */
				[self addClientSegment:segment];
				[self setStatus:STATUS_FIN_WAIT_CLIENT_2];
			}
		} else if([segment seqNo] == m_c_seq_no) {
			/* we still need to accept data in this half-closed state */
			[self addClientSegment:segment];
			if([segment finFlag]) /* simultaneous close */
				[self setStatus:STATUS_SIMULTANEOUS_CLOSE];
		} else {
			/* out of order */
			if(TCP_SEQ_LT([segment seqNo], m_c_seq_no)) {
				/* max segment size acts as a 'window size' here */
				if(TCPDECODE_SEQNO_NEXT(segment) > m_c_seq_no)
					[self addClientSegment:segment];
				/* otherwise discard the segment */
				return SEGMENT_ACCEPT;
			}
			return SEGMENT_REJECT;
		}
	} else { /* server segment */
		/* if the client is still sending data, we need to accept ack sent in reply */
		if([segment seqNo] == m_s_seq_no)
			[self addServerSegment:segment];
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketFinWaitServer1:(TCPDecode *)segment
{
	/* client sent fin, waiting for server fin */
	if([self segmentIsClient:segment]) {
		/* if the server is still sending data, we need to accept ack sent in reply */
		if([segment seqNo] == m_c_seq_no)
			[self addClientSegment:segment];
	} else { /* server segment */
		if([segment seqNo] == m_s_seq_no && [segment ackFlag] && TCP_SEQ_GE([segment ackNo], m_c_seq_no)) {
			if([segment finFlag]) { /* fin,ack */
				[self addServerSegment:segment];
				[self setStatus:STATUS_ACK_WAIT_CLIENT];
			} else { /* ack only */
				[self addServerSegment:segment];
				[self setStatus:STATUS_FIN_WAIT_SERVER_2];
			}
		} else if([segment seqNo] == m_s_seq_no) {
			/* we still need to accept data in this half-closed state */
			[self addServerSegment:segment];
			if([segment finFlag]) /* simultaneous close */
				[self setStatus:STATUS_SIMULTANEOUS_CLOSE];
		} else {
			/* out of order */
			if(TCP_SEQ_LT([segment seqNo], m_s_seq_no)) {
				/* max segment size acts as a 'window size' here */
				if(TCPDECODE_SEQNO_NEXT(segment) > m_s_seq_no)
					[self addServerSegment:segment];
				/* otherwise discard the segment */
				return SEGMENT_ACCEPT;
			}
			return SEGMENT_REJECT;
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addSimultaneousClose:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment seqNo] == m_c_seq_no) {
			[self addClientSegment:segment];
			if([segment ackFlag] && TCP_SEQ_GE([segment ackNo], m_s_seq_no))
				[self setStatus:STATUS_ACK_WAIT_SERVER];
		}
	} else { /* server segment */
		if([segment seqNo] == m_s_seq_no) {
			[self addServerSegment:segment];
			if([segment ackFlag] && TCP_SEQ_GE([segment ackNo], m_c_seq_no))
				[self setStatus:STATUS_ACK_WAIT_CLIENT];
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketFinWaitClient2:(TCPDecode *)segment
{
	/* server sent fin, client ack'ed fin, waiting for client fin */
	if([self segmentIsClient:segment]) {
		if([segment seqNo] == m_c_seq_no) {
			[self addClientSegment:segment];
			if([segment finFlag])
				[self setStatus:STATUS_ACK_WAIT_SERVER];
		} else {
			/* out of order */
			if(TCP_SEQ_LT([segment seqNo], m_c_seq_no)) {
				/* max segment size acts as a 'window size' here */
				if(TCPDECODE_SEQNO_NEXT(segment) > m_c_seq_no)
					[self addClientSegment:segment];
				/* otherwise discard the segment */
				return SEGMENT_ACCEPT;
			}
			return SEGMENT_REJECT;
		}
	} else { /* server segment */
		/* if the client is still sending data, we need to accept ack sent in reply */
		if([segment seqNo] == m_s_seq_no)
			[self addServerSegment:segment];
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketFinWaitServer2:(TCPDecode *)segment
{
	/* client sent fin, server ack'ed fin, waiting for server fin */
	if([self segmentIsClient:segment]) {
		/* if the server is still sending data, we need to accept ack sent in reply */
		if([segment seqNo] == m_c_seq_no)
			[self addClientSegment:segment];
	} else { /* server segment */
		if([segment seqNo] == m_s_seq_no) {
			[self addServerSegment:segment];
			if([segment finFlag])
				[self setStatus:STATUS_ACK_WAIT_CLIENT];
		} else {
			/* out of order */
			if(TCP_SEQ_LT([segment seqNo], m_s_seq_no)) {
				/* max segment size acts as a 'window size' here */
				if(TCPDECODE_SEQNO_NEXT(segment) > m_s_seq_no)
					[self addServerSegment:segment];
				/* otherwise discard the segment */
				return SEGMENT_ACCEPT;
			}
			return SEGMENT_REJECT;
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketAckWaitClient:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment seqNo] == m_c_seq_no)
			[self addClientSegment:segment];
			if([segment ackFlag] && TCP_SEQ_GE([segment ackNo], m_s_seq_no))
				[self setStatus:STATUS_TIME_WAIT];
	} else { /* server segment */
		if([segment seqNo] == m_s_seq_no)
			[self addServerSegment:segment];
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketAckWaitServer:(TCPDecode *)segment
{
	if([self segmentIsClient:segment]) {
		if([segment seqNo] == m_c_seq_no)
			[self addClientSegment:segment];
	} else {
		if([segment seqNo] == m_s_seq_no) {
			[self addServerSegment:segment];
			if([segment ackFlag] && TCP_SEQ_GE([segment ackNo], m_c_seq_no))
				[self setStatus:STATUS_TIME_WAIT];
		}
	}
	return SEGMENT_ACCEPT;
}

- (enum segment_action)addPacketTimeWait:(TCPDecode *)segment
{
	/* Assume (no justification for you) that SO_REUSEADDR and SO_REUSEPORT are not the common case */
	if([[segment date] timeIntervalSinceDate:[[m_packets lastObject] date]] <= (PPTCPSTREAM_MSL * 2))
		return SEGMENT_ACCEPT;

	[self setStatus:STATUS_CLOSED];

	return [self addPacketClosed:segment];
}

- (void)addSegment:(TCPDecode *)segment
{
	if([self segmentIsClient:segment])
		[self addClientSegment:segment];
	else
		[self addServerSegment:segment];
}

- (void)addClientSegment:(TCPDecode *)segment
{
	m_c_seq_no = TCPDECODE_SEQNO_NEXT(segment);
	[self incrementClientSegmentBytes:segment];
	[segment setBackPointer:self];
	[m_packets addObject:[segment parent]];
	[m_clientSegments addObject:segment];
}

- (void)addServerSegment:(TCPDecode *)segment
{
	m_s_seq_no = TCPDECODE_SEQNO_NEXT(segment);
	[self incrementServerSegmentBytes:segment];
	[segment setBackPointer:self];
	[m_packets addObject:[segment parent]];
	[m_serverSegments addObject:segment];
}

- (void)addSegment:(TCPDecode *)segment toQueue:(NSMutableArray *)queue
{
	TCPDecode *queueSegment;
	unsigned int i;

	if([queue count] > PPTCPSTREAM_QUEUE_MAX)
		return;

	for(i = [queue count]; i > 0; --i) {
		queueSegment = [queue objectAtIndex:i - 1];
		if(TCP_SEQ_GT([segment seqNo], [queueSegment seqNo]))
			break;
	}
	[segment setBackPointer:self];
	[queue insertObject:segment atIndex:i];
}

- (unsigned int)packetsCount
{
	return [m_packets count];
}

- (Packet *)packetAtIndex:(int)index
{
	if(index >= 0 && index < [m_packets count])	
		return [m_packets objectAtIndex:index];

	return nil;
}

- (TCPDecode *)segmentAtIndex:(int)index
{
	/* XXX this might be slow, due to the decoderForClass; TODO: measure it */
	if(index >= 0 && index < [m_packets count])	
		return [[m_packets objectAtIndex:index] decoderForClass:[TCPDecode class]];

	return nil;
}

- (unsigned int)clientSegmentsCount
{
	return [m_clientSegments count];
}

- (TCPDecode *)clientSegmentAtIndex:(int)index
{
	if(index >= 0 && index < [m_clientSegments count])	
		return [m_clientSegments objectAtIndex:index];

	return nil;
}

- (unsigned int)serverSegmentsCount
{
	return [m_serverSegments count];
}

- (TCPDecode *)serverSegmentAtIndex:(int)index
{
	if(index >= 0 && index < [m_serverSegments count])	
		return [m_serverSegments objectAtIndex:index];

	return nil;
}

- (NSString *)addrTo
{
	return ipaddrstr(&m_client_dstip, sizeof(m_client_dstip));
}

- (NSString *)addrFrom
{
	return ipaddrstr(&m_client_srcip, sizeof(m_client_srcip));
}

- (NSString *)hostTo
{
	if([m_packets count] < 1)
		return @"None";

	if([self segmentIsClient:[self segmentAtIndex:0]])
		return [[[m_packets objectAtIndex:0] decoderForClass:[IPV4Decode class]] to];
	else
		return [[[m_packets objectAtIndex:0] decoderForClass:[IPV4Decode class]] from];
}

- (NSString *)hostFrom
{
	if([m_packets count] < 1)
		return @"None";

	if([self segmentIsClient:[self segmentAtIndex:0]])
		return [[[m_packets objectAtIndex:0] decoderForClass:[IPV4Decode class]] from];
	else
		return [[[m_packets objectAtIndex:0] decoderForClass:[IPV4Decode class]] to];
}

- (NSString *)status
{
	NSString *statusString;

	switch(m_status) {
		case STATUS_CLOSED:
			statusString = @"Closed";
			break;
		case STATUS_SYN_SENT:
		case STATUS_SYN_ACK_RECV:
			statusString = @"SYN Sent";
			break;
		case STATUS_SIMULTANEOUS_OPEN:
		case STATUS_SIMULTANEOUS_SYN_ACK_WAIT_CLIENT:
		case STATUS_SIMULTANEOUS_SYN_ACK_WAIT_SERVER:
		case STATUS_SIMULTANEOUS_SYN_ACK_WAIT_CLIENT_2:
		case STATUS_SIMULTANEOUS_SYN_ACK_WAIT_SERVER_2:
			statusString = @"Simultaneous open";
			break;
		case STATUS_ESTABLISHED:
			statusString = @"Established";
			break;
		case STATUS_ACK_WAIT_CLIENT:
		case STATUS_ACK_WAIT_SERVER:
		case STATUS_SIMULTANEOUS_CLOSE:
		case STATUS_CLOSING:
			statusString = @"Closing";
			break;
		case STATUS_FIN_WAIT_CLIENT_1:
		case STATUS_FIN_WAIT_SERVER_1:
			statusString = @"FIN Wait 1";
			break;
		case STATUS_FIN_WAIT_CLIENT_2:
		case STATUS_FIN_WAIT_SERVER_2:
			statusString = @"FIN Wait 2";
			break;
		case STATUS_TIME_WAIT:
			statusString = @"Time Wait";
			break;
		default:
			statusString = @"Uninitialised";
			break;
	}

	if([m_packets count] > 0) {
		if(m_status == STATUS_TIME_WAIT && [[NSDate date] timeIntervalSinceDate:[[m_packets lastObject] date]] > (PPTCPSTREAM_MSL * 2))
			[self setStatus:STATUS_CLOSED];

		if(m_status != STATUS_CLOSED && m_status != STATUS_TIME_WAIT && [[NSDate date] timeIntervalSinceDate:[[m_packets lastObject] date]] > PPTCPSTREAM_MSL)
			return [NSString stringWithFormat:@"%@ (timeout)", statusString];
	}

	return statusString;
}

- (unsigned int)srcPort
{
	return m_client_sport;
}

- (unsigned int)dstPort
{
	return m_client_dport;
}

- (NSString *)srcPortName
{
	if([m_packets count] < 1)
		return @"None";

	if([self segmentIsClient:[self segmentAtIndex:0]])
		return [[self segmentAtIndex:0] srcPortName];
	else
		return [[self segmentAtIndex:0] dstPortName];
}

- (NSString *)dstPortName
{
	if([m_packets count] < 1)
		return @"None";

	if([self segmentIsClient:[self segmentAtIndex:0]])
		return [[self segmentAtIndex:0] dstPortName];
	else
		return [[self segmentAtIndex:0] srcPortName];
}

- (unsigned long long)bytesSent
{
	return m_client_nbytes;
}

- (unsigned long)bytesReceived
{
	return m_server_nbytes;
}

- (unsigned long long)totalBytes
{
	if(m_client_nbytes > ULLONG_MAX - m_server_nbytes)
		return ULLONG_MAX;

	return m_client_nbytes + m_server_nbytes;
}

- (BOOL)isValid
{
	return m_isValid && ([m_clientSegments count] > 0 || [m_serverSegments count] > 0);
}

- (BOOL)isDisplayed
{
	return m_isDisplayed;
}

- (void)setDisplayed:(BOOL)isDisplayed
{
	m_isDisplayed = isDisplayed;
}

- (NSComparisonResult)compare:(PPTCPStream *)stream atIndex:(unsigned int)fieldIndex
{
	switch(fieldIndex) {
		case PPSTREAM_SORT_SRC_IP_ADDRESS:
			return [[self addrFrom] compare:[stream addrFrom]];

		case PPSTREAM_SORT_DST_IP_ADDRESS:
			return [[self addrTo] compare:[stream addrTo]];

		case PPSTREAM_SORT_SRC_HOSTNAME:
			return [[self hostFrom] compare:[stream hostFrom]];

		case PPSTREAM_SORT_DST_HOSTNAME:
			return [[self hostTo] compare:[stream hostTo]];

		case PPSTREAM_SORT_SRC_PORT:
			return val_compare([self srcPort], [stream srcPort]);

		case PPSTREAM_SORT_DST_PORT:
			return val_compare([self dstPort], [stream dstPort]);

		case PPSTREAM_SORT_SRC_PORTNAME:
			return [[self srcPortName] compare:[stream srcPortName]];

		case PPSTREAM_SORT_DST_PORTNAME:
			return [[self dstPortName] compare:[stream dstPortName]];

		case PPSTREAM_SORT_BYTES_SENT:
			return val_compare([self bytesSent], [stream bytesSent]);

		case PPSTREAM_SORT_BYTES_RECV:
			return val_compare([self bytesReceived], [stream bytesReceived]);

		case PPSTREAM_SORT_BYTES_TOTAL:
			return val_compare([self totalBytes], [stream totalBytes]);

		case PPSTREAM_SORT_STATUS:
			return [[self status] compare:[stream status]];
	}
	return NSOrderedSame;
}

- (void)removeAllPackets
{
	unsigned int i;

	/* clear all TCPDecode back pointers */

	for(i = 0; i < [m_clientSegments count]; ++i)
		[[m_clientSegments objectAtIndex:i] setBackPointer:NULL];

	for(i = 0; i < [m_serverSegments count]; ++i)
		[[m_serverSegments objectAtIndex:i] setBackPointer:NULL];

	for(i = 0; i < [m_clientQueue count]; ++i)
		[[m_clientQueue objectAtIndex:i] setBackPointer:NULL];

	for(i = 0; i < [m_serverQueue count]; ++i)
		[[m_serverQueue objectAtIndex:i] setBackPointer:NULL];

	[m_packets removeAllObjects];
	[m_clientSegments removeAllObjects];
	[m_serverSegments removeAllObjects];
	[m_clientQueue removeAllObjects];
	[m_serverQueue removeAllObjects];
}

- (void)removePacketsAtIndexes:(NSIndexSet *)indexSet
{
	NSRange range;
	unsigned int i, n;
	NSUInteger indexes[128];

	range.location = [indexSet firstIndex];
	range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

	while((n = [indexSet getIndexes:indexes maxCount:(sizeof(indexes) / sizeof(indexes[0])) inIndexRange:&range]) > 0) {
		for(i = 0; i < n; ++i) {
			TCPDecode *segment;

			if((segment = [[m_packets objectAtIndex:indexes[i]] decoderForClass:[TCPDecode class]]) != nil) {
				/* slow... */
				[segment setBackPointer:NULL];
				[m_serverSegments removeFirstObjectIdenticalTo:segment];
				[m_clientSegments removeFirstObjectIdenticalTo:segment];
				[m_clientQueue removeFirstObjectIdenticalTo:segment];
				[m_serverQueue removeFirstObjectIdenticalTo:segment];
			}
		}
	}

	[m_packets removeObjectsAtIndexes:indexSet];

	if(m_streamReassembler != nil)
		[m_streamReassembler noteSegmentsDeleted];
}

- (void)removePacket:(Packet *)packet
{
	TCPDecode *segment;

	if((segment = [packet decoderForClass:[TCPDecode class]]) == nil)
		return;

	[segment setBackPointer:NULL];
	[m_packets removeFirstObjectIdenticalTo:packet];
	[m_serverSegments removeFirstObjectIdenticalTo:segment];
	[m_clientSegments removeFirstObjectIdenticalTo:segment];
	[m_clientQueue removeFirstObjectIdenticalTo:segment];
	[m_serverQueue removeFirstObjectIdenticalTo:segment];

	if(m_streamReassembler != nil)
		[m_streamReassembler noteSegmentsDeleted];
}

- (BOOL)containsPacket:(Packet *)packet
{
	TCPDecode *segment;

	if((segment = [packet decoderForClass:[TCPDecode class]]) == nil)
		return NO;

	return([m_packets containsObject:packet] ||
		   [m_serverSegments containsObject:segment] ||
		   [m_clientSegments containsObject:segment] ||
		   [m_clientQueue containsObject:segment] ||
		   [m_serverQueue containsObject:segment]);
}

- (void)dealloc
{
	[m_streamReassembler release];
	[self removeAllPackets]; /* clears TCPDecode back pointers */
	[m_packets release];
	[m_serverSegments release];
	[m_clientSegments release];
	[m_clientQueue release];
	[m_serverQueue release];
	[super dealloc];
}

@end
