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

#ifndef _PPTCPSTREAM_H_
#define _PPTCPSTREAM_H_

#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#import <Foundation/NSObject.h>

#define PPSTREAM_SORT_SRC_IP_ADDRESS		1
#define PPSTREAM_SORT_DST_IP_ADDRESS		2
#define PPSTREAM_SORT_SRC_HOSTNAME			3
#define PPSTREAM_SORT_DST_HOSTNAME			4
#define PPSTREAM_SORT_SRC_PORT				5
#define PPSTREAM_SORT_DST_PORT				6
#define PPSTREAM_SORT_SRC_PORTNAME			7
#define PPSTREAM_SORT_DST_PORTNAME			8
#define PPSTREAM_SORT_BYTES_SENT			9
#define PPSTREAM_SORT_BYTES_RECV			10
#define PPSTREAM_SORT_BYTES_TOTAL			11
#define PPSTREAM_SORT_STATUS				12

#define PPTCPSTREAM_MSL						120.0 /* 2 minutes as per RFC 793 (usually 30 seconds though) */
/* XXX QUEUE_MAX will be replaced by handling window sizes */
#define PPTCPSTREAM_QUEUE_MAX				(16 * 1024)	/* maximum number of segments permitted on out of order queue */
#define PPTCPSTREAM_REASSEMBLY_WINDOW_SZ	(8 * 1024 * 1024)
#define TCP_SEQ_EQ(s1, s2)					((s1) == (s2))
#define TCP_SEQ_GT(s1, s2)					(((s1) > (s2) && (s1) - (s2) <= (UINT32_MAX / 2U)) || ((s2) > (s1) && (s2) - (s1) > (UINT32_MAX / 2U)))
#define TCP_SEQ_LT(s1, s2)					TCP_SEQ_GE(s2, s1)
#define TCP_SEQ_GE(s1, s2)					(TCP_SEQ_EQ(s1, s2) || TCP_SEQ_GT(s1, s2))
#define TCP_SEQ_LE(s1, s2)					(TCP_SEQ_EQ(s1, s2) || TCP_SEQ_LT(s1, s2))

/* evaluates s1 - s2. pre-condition ==> TCP_SEQ_GT(s1, s2) == True */
#define TCP_SEQNO_DIFF(s1, s2)			((s1) - (s2) <= (UINT32_MAX / 2U) ? (s1) - (s2) : ((s1) - (s2)) + UINT_MAX)

/* calculates next sequence number expected after segment s */
#define TCPDECODE_SEQNO_NEXT(s)			([(s) seqNo] + [(s) size] + ([(s) synFlag] ? 1 : ([(s) finFlag] ? 1 : 0)))

@class NSMutableArray;
@class NSIndexSet;
@class TCPDecode;
@class Packet;
@class PPTCPStreamReassembler;

enum segment_action {SEGMENT_ACCEPT, SEGMENT_REJECT, SEGMENT_DISCARD};

enum stream_status {STATUS_UNINITIALISED,
					STATUS_CLOSED,
					STATUS_SYN_SENT,
					STATUS_SIMULTANEOUS_OPEN,
					STATUS_SIMULTANEOUS_SYN_ACK_WAIT_CLIENT,
					STATUS_SIMULTANEOUS_SYN_ACK_WAIT_SERVER,
					STATUS_SIMULTANEOUS_SYN_ACK_WAIT_CLIENT_2,
					STATUS_SIMULTANEOUS_SYN_ACK_WAIT_SERVER_2,
					STATUS_SIMULTANEOUS_ACK_WAIT_CLIENT,
					STATUS_SIMULTANEOUS_ACK_WAIT_SERVER,
					STATUS_SYN_ACK_RECV,
					STATUS_ESTABLISHED,
					STATUS_FIN_WAIT_CLIENT_1,
					STATUS_FIN_WAIT_SERVER_1,
					STATUS_FIN_WAIT_CLIENT_2,
					STATUS_FIN_WAIT_SERVER_2,
					STATUS_CLOSING,
					STATUS_ACK_WAIT_CLIENT, /* waiting for fin to be acked */
					STATUS_ACK_WAIT_SERVER, /* waiting for fin to be acked */
					STATUS_TIME_WAIT,
					STATUS_SIMULTANEOUS_CLOSE,
					STATUS_NELEMS};

@interface PPTCPStream : NSObject {
	PPTCPStreamReassembler *m_streamReassembler;
	NSMutableArray *m_packets;
	NSMutableArray *m_serverSegments;
	NSMutableArray *m_clientSegments;
	NSMutableArray *m_clientQueue;		/* queue for out of order packets set by server */
	NSMutableArray *m_serverQueue;		/* queue for out of order packets sent by client */
	unsigned long long m_client_nbytes;	/* nbytes sent by the `client' */
	unsigned long long m_server_nbytes;	/* nbytes sent by the `server' */
	enum stream_status m_status;
	/* first packets source ip/port, used to determine a packets direction */
	struct in_addr m_client_srcip;
	struct in_addr m_client_dstip;
	uint16_t m_client_sport;
	uint16_t m_client_dport;
	BOOL m_isValid;
	BOOL m_isDisplayed;

	/* variables used to record book-keeping info within a state. */
	uint32_t m_c_seq_no;
	uint32_t m_s_seq_no;
}

- (void)setStreamReassembler:(PPTCPStreamReassembler *)streamReassembler;
- (PPTCPStreamReassembler *)streamReassembler;
- (void)setStatus:(enum stream_status)status; /* private method */
- (void)setClientSegment:(TCPDecode *)segment; /* private method */
- (BOOL)segmentIsClient:(TCPDecode *)segment;
- (BOOL)segmentIsServer:(TCPDecode *)segment;
- (void)incrementServerSegmentBytes:(TCPDecode *)segment; /* private method */
- (void)incrementClientSegmentBytes:(TCPDecode *)segment; /* private method */

- (BOOL)addPacket:(Packet *)packet;
- (enum segment_action)addPacketUninitialised:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketClosed:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketSynSent:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketSimultaneousOpen:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketSimultaneousSynAckWaitClient:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketSimultaneousSynAckWaitServer:(TCPDecode *)segment; /* private method */

- (enum segment_action)addPacketSimultaneousSynAckWaitClient2:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketSimultaneousSynAckWaitServer2:(TCPDecode *)segment; /* private method */

- (enum segment_action)addPacketSynAckRecv:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketEstablished:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketFinWaitClient1:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketFinWaitServer1:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketFinWaitClient2:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketFinWaitServer2:(TCPDecode *)segment; /* private method */
- (enum segment_action)addSimultaneousClose:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketAckWaitClient:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketAckWaitServer:(TCPDecode *)segment; /* private method */
- (enum segment_action)addPacketTimeWait:(TCPDecode *)segment; /* private method */

- (void)addSegment:(TCPDecode *)segment; /* private method */
- (void)addClientSegment:(TCPDecode *)segment; /* private method */
- (void)addServerSegment:(TCPDecode *)segment; /* private method */

- (void)addSegment:(TCPDecode *)segment toQueue:(NSMutableArray *)queue;

- (unsigned int)packetsCount;
- (Packet *)packetAtIndex:(int)index;
- (TCPDecode *)segmentAtIndex:(int)index;

- (unsigned int)clientSegmentsCount;
- (TCPDecode *)clientSegmentAtIndex:(int)index;

- (unsigned int)serverSegmentsCount;
- (TCPDecode *)serverSegmentAtIndex:(int)index;

- (NSString *)addrTo;
- (NSString *)addrFrom;
- (NSString *)hostTo;
- (NSString *)hostFrom;
- (NSString *)status;
- (unsigned int)srcPort;
- (unsigned int)dstPort;
- (NSString *)srcPortName;
- (NSString *)dstPortName;
- (unsigned long long)bytesSent;
- (unsigned long )bytesReceived;
- (unsigned long long)totalBytes;
- (BOOL)isValid;
- (BOOL)isDisplayed;
- (void)setDisplayed:(BOOL)isDisplayed;

- (NSComparisonResult)compare:(PPTCPStream *)stream atIndex:(unsigned int)index;

- (void)removeAllPackets;
- (void)removePacketsAtIndexes:(NSIndexSet *)indexSet;
- (void)removePacket:(Packet *)packet;
- (BOOL)containsPacket:(Packet *)packet;

@end

#endif
