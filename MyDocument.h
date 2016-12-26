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

#ifndef PACKETPEEPER_MYDOCUMENT_H
#define PACKETPEEPER_MYDOCUMENT_H

#include <CoreFoundation/CFSocket.h>
#import <AppKit/NSDocument.h>
#import <AppKit/NSAlert.h>
#include "pkt_compare.h"

#define BPF_SMALLBUFSIZE	0x80
#define BPF_MEDIUMBUFSIZE	0x400
#define BPF_LARGEBUFSIZE	0x2000

#define CAPTURE_FILE_LOADING_ARRAY_SZ	1024

#define PPDocumentSaveOperationSucceededNotification	@"PPSaveSucceeded"
#define PPDocumentSaveOperationFailedNotification		@"PPSaveFailed"

/* note that BS_HUGE is chosen as default,
   as the bpf device chooses the largest buffer
   itself if unspecified by the user */

enum _bufsize {BS_TINY,
			   BS_SMALL,
			   BS_MEDIUM,
			   BS_LARGE,
			   BS_HUGE};

typedef enum _bufsize bufsize;

@class NSString;
@class NSArray;
@class NSMutableArray;
@class NSTimer;
@class NSSocketPort;
@class NSTimer;
@class NSURL;
@class NSError;
@class NSFont;
@class PacketCaptureWindowController;
@class PPCaptureFilterWindowController;
@class PPProgressWindowController;
@class PPNodeGraphController;
@class ObjectIO;
@class Packet;
@class PPTCPStreamController;
@class PPTCPStream;
@class Interface;
@class PPCaptureFilter;
@class PPBPFProgram;
@class PPStreamsWindowController;
@class PPArpSpoofingWindowController;
@class ColumnIdentifier;
@class HostCache;
@class ErrorStack;

struct thread_args;

@interface MyDocument : NSDocument
{
	PacketCaptureWindowController *captureWindowController;
	PPStreamsWindowController *streamsWindowController;
	PPArpSpoofingWindowController *arpSpoofingWindowController;
	PPProgressWindowController *progressWindowController;
	ObjectIO *helperIO;
	PPTCPStreamController *streamController;
	HostCache *hc;
	NSMutableArray *packets;
	NSMutableArray *allPackets;
	NSTimer *timer;
	NSString *interface;
	ColumnIdentifier *sortColumn;
	PPBPFProgram *bpfProgram;
	struct thread_args *thread_args;
	size_t byteCount;
	CFSocketRef sockref;
	unsigned long packetCount;
	int sockfd;
	int linkType;
	BOOL live;			/* is the current document a live capture */
	BOOL reverseOrder;	/* is the packet array currently in reverse order? */

	/* capture ending conditions */
	NSTimer *endingTimer;
	unsigned long endingPackets;
	unsigned long long endingBytes;
	BOOL endingMatchAll;
}

- (void)waitForWorkerThread;
- (void)workerThreadTimer;
- (void)cancelWorkerThread;
- (void)cancelCaptureFilterExecution;
- (void)cancelLoadingFile;
- (void)cancelSavingFile;
- (void)closeProgressSheet;
- (void)displayFileLoadingProgressSheet;
- (void)displayProgressSheetWithMessage:(NSString *)message cancelSelector:(SEL)cancelSelector;
- (void)displayFilterSheet;
- (void)displaySetupSheet;
- (void)displayIndividualWindow:(Packet *)aPacket;
- (void)displayReassemblyWindowForPacket:(Packet *)aPacket;
- (void)displayNodeGraphWindow;
- (void)displayStreamsWindow;
- (void)displayArpSpoofingWindow;

- (PacketCaptureWindowController *)packetCaptureWindowController;

//- (void)setNodeGraphController:(PPNodeGraphController *)aNodeGraphController;

- (BOOL)isSaveOperationInProgress;
- (BOOL)isLive;
- (int)linkType;
- (void)setHostCache:(HostCache *)hostCache;
- (HostCache *)hostCache;
- (NSString *)interface;
- (void)setInterface:(NSString *)anInterface;
- (Packet *)packetAtIndex:(NSInteger)packetIndex;
- (size_t)numberOfPackets;
- (size_t)numberOfBytes;
- (void)deletePacketAtIndex:(NSInteger)packetIndex;
- (void)updateControllers;
- (void)addPacketArray:(NSArray *)packetArray;
- (void)addPacket:(Packet *)packet;
- (void)deletePacket:(Packet *)packet;
- (void)deleteStream:(PPTCPStream *)stream streamIndex:(NSUInteger)streamIndex indexValid:(BOOL)indexValid;
- (void)deleteStream:(PPTCPStream *)stream streamIndex:(NSUInteger)streamIndex;
- (void)deleteStream:(PPTCPStream *)stream;
- (NSArray *)packetsSortedByNumber;
- (void)sortPacketsWithColumn:(ColumnIdentifier *)column;
- (void)setReversePacketOrder:(BOOL)reverse;
- (BOOL)isReverseOrder;
- (NSInteger)indexForPacket:(Packet *)packet;

- (PPTCPStreamController *)tcpStreamController;

- (void)displayErrorStack:(ErrorStack *)errorStack close:(BOOL)closeDocument; // XXX perhaps move to PCWC

- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(NSModalResponse)returnCode contextInfo:(void *)contextInfo;

- (void)startCaptureOn:(Interface *)anInterface
					   isPromiscuous:(BOOL)promiscuousVal
					   isRealTime:(BOOL)realTimeVal
					   bufferLength:(bufsize)bufferLengthVal
					   updateFrequency:(float)frequency
					   stopAfterPackets:(unsigned long)numberOfPackets
					   stopAfterDate:(NSDate *)stopDate
					   stopAfterData:(unsigned long long)numberOfBytes
					   stopAfterMatchAll:(BOOL)matchAllConditions
					   filter:(PPCaptureFilter *)filter;

- (void)purgePacketsPendingDeletionWithHint:(size_t)count;

- (void)flushHostnames;

- (void)stopCapture;

- (void)updateControllerWithTimer:(NSTimer *)aTimer;
- (void)endCaptureWithTimer:(NSTimer *)aTimer;
- (void)cancelEndingConditions;

- (void)readData;
- (void)clearFilterProgram:(BOOL)discardFilteredPackets;
- (PPBPFProgram *)filterProgram;
- (void)setCaptureFilter:(PPCaptureFilter *)captureFilter;

@end

#endif

