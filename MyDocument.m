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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/bpf.h>
#include <time.h>
#include <pcap.h>
#include <libkern/OSAtomic.h>
#include <CoreFoundation/CFSocket.h>
#include <assert.h>
#import <Foundation/NSThread.h>
#import <Foundation/NSObject.h>
#import <Foundation/NSNull.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSFileWrapper.h>
#import <Foundation/NSError.h>
#import <Foundation/NSUserDefaults.h>
#import <Foundation/NSRunLoop.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSData.h>
#import <Foundation/NSTimer.h>
#import <Foundation/NSArchiver.h>
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSURL.h>
#import <Foundation/NSString.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSEvent.h>
#import <AppKit/NSWindowController.h>
#import <AppKit/NSPanel.h>
#import <AppKit/NSFont.h>
#import <AppKit/NSDocument.h>
#import <AppKit/NSWindowRestoration.h>
#include "pktap.h"
#include "ObjectIO.h"
#include "AppController.h"
#include "Describe.h"
#include "Messages.h"
#include "Packet.h"
#include "PPPacketUIAdditons.h"
#include "LoopbackDecode.h"
#include "PPPDecode.h"
#include "EthernetDecode.h"
#include "IPV4Decode.h"
#include "TCPDecode.h"
#include "PPRVIDecode.h"
#include "Interface.h"
#include "PPCaptureFilter.h"
#include "PPBPFProgram.h"
#include "PPBPFProgram.h"
#include "PPTCPStreamController.h"
#include "PPTCPStreamReassembler.h"
#include "PPTCPStream.h"
#include "PacketCaptureWindowController.h"
#include "PPTCPStreamWindowController.h"
#include "PPStreamsWindowController.h"
#include "PPArpSpoofingWindowController.h"
#include "CaptureSetupWindowController.h"
#include "PPCaptureFilterWindowController.h"
#include "PPProgressWindowController.h"
#include "ErrorReportWindowController.h"
#include "MyDocumentController.h"
#include "HostCache.hh"
#include "ErrorStack.h"
#include "DateFormat.h"
#include "PacketPeeper.h"
#include "dlt_lookup.h"
#include "MyDocument.h"

static void socketCallBack(CFSocketRef s, CFSocketCallBackType callbackType, CFDataRef address, const void *data, void *info);
static void *read_from_url_thread(void *args);
static void *filter_packets_thread(void *args);

struct thread_args {
	enum {THREAD_OP_DOC_READ, THREAD_OP_DOC_FILTER} op;
	id input[3];
	volatile id output[2];
	NSTimer *timer;
	volatile int cancel;
	volatile int failure;
	volatile int success;
	volatile unsigned long long units_current;
	volatile unsigned long long units_total;
	volatile size_t nbytes;
	pthread_t thread_id;
};

@implementation MyDocument

- (id)init
{
    if((self = [super init]) != nil) {
		packets = [[NSMutableArray alloc] init];
		allPackets = nil;
		streamController = [[PPTCPStreamController alloc] init];
		captureWindowController = nil;
		streamsWindowController = nil;
		progressWindowController = nil;
		helperIO = nil;
		timer = nil;
		hc = nil;
		interface = nil;
		sortColumn = nil; /* sort by packet number */
		bpfProgram = nil;
		sockref = NULL;
		packetCount = 0;
		byteCount = 0;
		sockfd = -1;
		live = NO;
		reverseOrder = NO;
		endingTimer = nil;
		linkType = -1;
		thread_args = NULL;
    }
    return self;
}

- (void)makeWindowControllers
{
	if(captureWindowController == nil) {
		captureWindowController = [[PacketCaptureWindowController alloc] initWithWindowNibName:@"MyDocument"];
		[self addWindowController:captureWindowController];
		[captureWindowController showWindow:self];
		/* hang on to captureWindowController--we release in dealloc */
	}
}

- (int)linkType
{
	if(linkType == -1) {
		if([packets count] > 0)
			linkType = [[packets objectAtIndex:0] linkType];
		else
			linkType = DLT_NULL;
	}

	return linkType;
}

- (BOOL)canAsynchronouslyWriteToURL:(NSURL *)url ofType:(NSString *)typeName forSaveOperation:(NSSaveOperationType)saveOperation
{
    return YES;
}

- (void)saveToURL:(NSURL *)url ofType:(NSString *)typeName forSaveOperation:(NSSaveOperationType)saveOperation completionHandler:(void (^)(NSError *errorOrNil))completionHandler
{
    [captureWindowController displaySavingIndicator];
    [super
        saveToURL:url
        ofType:typeName
        forSaveOperation:saveOperation
        completionHandler:
            ^(NSError *errorOrNil)
            {
                [captureWindowController hideSavingIndicator];
                completionHandler(errorOrNil);
            }];
}

- (BOOL)writeToURL:(NSURL *)absoluteURL ofType:(NSString *)typeName error:(NSError **)outError
{
    // Note that this function is not invoked on the main thread as canAsynchronouslyWriteToURL returns YES
	NSString *errorString;
	NSDictionary *errDict;

    if(![typeName isEqualToString:@"tcpdump"])
        return NO;

    NSMutableArray* savePackets = [NSMutableArray arrayWithArray:allPackets != nil ? allPackets : packets]; // autoreleased

    [self unblockUserInteraction];

    [savePackets sortUsingFunction:pkt_compare context:nil];

    // If we have an RVI/PKTAP capture that was captured live then strip off the
    // pktap header to keep compatibility with other sniffers. This is needed
    // because Apple used a DLT_USER value for the DLT instead of getting a
    // proper DLT value assigned. Technically Packet Peeper is incorrect for
    // assuming that a DLT of 149 is RVI/PKTAP.
    const BOOL stripPkTap =
        [[savePackets objectAtIndex:0] linkType] == DLT_PKTAP &&
        [[[[savePackets objectAtIndex:0] decoders] objectAtIndex:0] class] == [PPRVIDecode class] &&
        ![interface isEqualToString:@"pcap"]; // interface is pcap if capture was loaded from disk

    int saveLinkType;

    if(stripPkTap) {
        saveLinkType = [[[[savePackets objectAtIndex:0] decoders] objectAtIndex:0] dlt];
    } else {
        saveLinkType = [[savePackets objectAtIndex:0] linkType];
    }

    pcap_t *pcap;
    if((pcap = pcap_open_dead(saveLinkType, BPF_MAXBUFSIZE)) == NULL) {
        errorString = @"pcap_open_dead failed";
        goto err;
    }

    pcap_dumper_t *dump;
    if((dump = pcap_dump_open(pcap, [[absoluteURL path] UTF8String])) == NULL) {
        errorString = [NSString stringWithUTF8String:pcap_geterr(pcap)];
        goto err;
    }

    for(Packet* pkt in savePackets)
    {
        struct pcap_pkthdr hdr;
        double seconds;

        hdr.ts.tv_usec = (suseconds_t)(modf([[pkt date] timeIntervalSince1970], &seconds) * 1000000.0);
        hdr.ts.tv_sec = (time_t)seconds;

        hdr.len = [pkt actualLength];
        hdr.caplen = [pkt captureLength];

        if(stripPkTap && [[[pkt decoders] objectAtIndex:0] class] == [PPRVIDecode class]) {
            // If the decoder at index 0 is a PPRVIDecoder then we know we got a complete
            // pktap header
            const size_t offset = [[[pkt decoders] objectAtIndex:0] frontSize];
            hdr.len -= offset;
            hdr.caplen -= offset;
            pcap_dump((unsigned char *)dump, &hdr, (unsigned char *)[[pkt packetData] bytes] + offset);
        } else {
            pcap_dump((unsigned char *)dump, &hdr, (unsigned char *)[[pkt packetData] bytes]);
        }
    }

    return YES;

err:
    errDict = [NSDictionary dictionaryWithObject:errorString forKey:NSLocalizedFailureReasonErrorKey];
    *outError = [[NSError alloc] initWithDomain:@"PacketPeeperErrorDomain" code:noErr userInfo:errDict];
    [*outError autorelease];
    return NO;
}

- (BOOL)readFromURL:(NSURL *)absoluteURL ofType:(NSString *)typeName error:(NSError **)outError
{
	NSString *errorString;
	NSDictionary *errDict;
	int ret;

    if (outError != NULL)
        *outError = nil;

	if(thread_args != NULL) {
		errorString = @"File loading or saving operation already in progress";
		goto err;
	}

	if(![typeName isEqualToString:@"tcpdump"] || ![absoluteURL isFileURL])
		return NO;

	if((thread_args = malloc(sizeof(struct thread_args))) == NULL) {
		errorString = [NSString stringWithFormat:@"Error: malloc failed: %s", strerror(errno)];
		goto err;
	}

	[self setInterface:@"pcap"];

	[packets removeAllObjects];
	[allPackets release];
	allPackets = nil;

	[hc release];
	hc = nil;

	[streamController flush];

	thread_args->op = THREAD_OP_DOC_READ;
	thread_args->input[0] = [absoluteURL retain];
	thread_args->input[1] = nil;
	thread_args->input[2] = nil;
	thread_args->output[0] = nil;
	thread_args->output[1] = nil;
	thread_args->cancel = 0;
	thread_args->failure = 0;
	thread_args->success = 0;
	thread_args->units_current = 0;
	thread_args->units_total = 0;

	if((ret = pthread_create(&thread_args->thread_id, NULL, read_from_url_thread, thread_args)) != 0) {
		errorString = [NSString stringWithFormat:@"Error: failed to create thread: %s", strerror(ret)];
		[thread_args->input[0] release];
		free(thread_args);
		thread_args = NULL;
        goto err;
	}

    [self makeWindowControllers];
    progressWindowController =
        [[PPProgressWindowController alloc] initWithLoadingMessage:@"Loading" delegate:self cancelSelector:@selector(cancelLoadingFile)];
    [self performSelector:@selector(displayFileLoadingProgressSheet) withObject:self afterDelay:0];

	thread_args->timer = [[NSTimer scheduledTimerWithTimeInterval:DEFAULT_PROGRESSBAR_UPDATE_FREQUENCY target:self selector:@selector(workerThreadTimer) userInfo:nil repeats:YES] retain];
	return YES;

err:
	[self closeProgressSheet];
	errDict = [NSDictionary dictionaryWithObject:errorString forKey:NSLocalizedFailureReasonErrorKey];
	*outError = [[NSError alloc] initWithDomain:@"PacketPeeperErrorDomain" code:noErr userInfo:errDict];
	[*outError autorelease];
	return NO;
}

- (void)waitForWorkerThread
{
	/* we don't need to specify an expiry date because thread_args->timer will fire regularly */
	while(thread_args != NULL)
		[NSApp nextEventMatchingMask:NSAnyEventMask untilDate:nil inMode:NSDefaultRunLoopMode dequeue:YES];
}

- (void)workerThreadTimer
{
	int ret;

	if(thread_args->units_total != 0) {
		const double percentLoaded = thread_args->units_current / (double)thread_args->units_total;
		[progressWindowController setPercentLoaded:percentLoaded];
	}

	if(thread_args->success || thread_args->failure) {
		NSTimer *tempTimer;

		tempTimer = thread_args->timer;

		[thread_args->input[0] release];
		[thread_args->input[1] release];
		[thread_args->input[2] release];

		[self closeProgressSheet];

		if((ret = pthread_join(thread_args->thread_id, NULL)) != 0) {
			NSString *errorString;
			BOOL shouldClose;

			shouldClose = (thread_args->op == THREAD_OP_DOC_READ) ? YES : NO;

			errorString = [NSString stringWithFormat:@"pthread_join(%p) failed", (void*)thread_args->thread_id];
			[[ErrorStack sharedErrorStack] pushError:errorString lookup:[PosixError class] code:ret severity:ERRS_ERROR];
			[thread_args->output[0] release];
			[thread_args->output[1] release];
			free(thread_args);
			thread_args = NULL;

			[self displayErrorStack:nil close:shouldClose];

			[tempTimer invalidate];
			[tempTimer release];
			return;
		}

		/* ensure thread_args->output is correct */
		OSMemoryBarrier();

		if(thread_args->success) {
			NSArray *windowControllers;
			NSWindowController *current;
			unsigned int i;

			if(thread_args->op == THREAD_OP_DOC_READ) {
				[packets release];
				packets = thread_args->output[0];

				[packets makeObjectsPerformSelector:@selector(setDocument:) withObject:self];

				[streamController release];
				streamController = thread_args->output[1];

				byteCount = thread_args->nbytes;

				[streamsWindowController tableViewSelectionDidChange:nil];
				[self updateControllers];

				windowControllers = [self windowControllers];

				for(i = 0; i < [windowControllers count]; ++i) {
					current = [windowControllers objectAtIndex:i];
					if(current != captureWindowController)
						[[current window] orderFront:self];
				}

				[[captureWindowController window] makeKeyAndOrderFront:self];
                [captureWindowController selectPacketAtIndex:0];
			} else if(thread_args->op == THREAD_OP_DOC_FILTER) {
				if(allPackets == nil)
					allPackets = packets;
				else
					[packets release];

				packets = thread_args->output[0];
				streamController = thread_args->output[1];

				[streamsWindowController tableViewSelectionDidChange:nil];
				[self updateControllers];
			}

			free(thread_args);
			thread_args = NULL;
			/* the timer needs to be released last, because it could be the last thing
			   retaining the document; dealloc calls cancelWorkerThread, which would lead
			   to a double free */
			[tempTimer invalidate];
			[tempTimer release];
		} else if(thread_args->failure) {
			if(thread_args->op == THREAD_OP_DOC_READ) {
				[[captureWindowController window] makeKeyAndOrderFront:self];
				[[ErrorStack sharedErrorStack] pushError:[NSString stringWithFormat:@"Loading capture file failed: %@", thread_args->output[0]] lookup:Nil code:0 severity:ERRS_ERROR];
				[self displayErrorStack:nil close:YES];
			} else if(thread_args->op == THREAD_OP_DOC_FILTER) {
				unsigned int i;

				/* restore released stream controller */
				streamController = [[PPTCPStreamController alloc] init];
				for(i = 0; i < [packets count]; ++i)
					[streamController addPacket:[packets objectAtIndex:i]];

				[[ErrorStack sharedErrorStack] pushError:[NSString stringWithFormat:@"Failed to apply filter: %@", thread_args->output[0]] lookup:Nil code:0 severity:ERRS_ERROR];
				[self displayErrorStack:nil close:NO];
			}

			[thread_args->output[0] release];
			[thread_args->output[1] release];
			free(thread_args);
			thread_args = NULL;
			[tempTimer invalidate];
			[tempTimer release];
		}
	}
}

- (void)cancelWorkerThread
{
	int ret;
	void *output;

	if(thread_args == NULL)
		return;

	[thread_args->timer invalidate];
	[thread_args->timer release];
	[thread_args->input[0] release];
	[thread_args->input[1] release];
	[thread_args->input[2] release];

	thread_args->cancel = 1;

	if((ret = pthread_join(thread_args->thread_id, &output)) != 0) {
		NSString *errorString;
		BOOL shouldClose;

		shouldClose = (thread_args->op == THREAD_OP_DOC_READ) ? YES : NO;

		errorString = [NSString stringWithFormat:@"pthread_join(%p) failed", (void*)thread_args->thread_id];
		[[ErrorStack sharedErrorStack] pushError:errorString lookup:[PosixError class] code:ret severity:ERRS_ERROR];
		[thread_args->output[0] autorelease];
		[thread_args->output[1] autorelease];
		free(thread_args);
		thread_args = NULL;
		[self displayErrorStack:nil close:shouldClose];
		return;
	}

	/* account for thread exiting by its own volition */
	if(output != NULL)
		[(NSObject *)output release];

	free(thread_args);
	thread_args = NULL;
}

- (void)cancelCaptureFilterExecution
{
	unsigned int i;

	[self closeProgressSheet];
	[self cancelWorkerThread];

	/* restore released stream controller */
	streamController = [[PPTCPStreamController alloc] init];
	for(i = 0; i < [packets count]; ++i)
		[streamController addPacket:[packets objectAtIndex:i]];
}

- (void)cancelLoadingFile
{
	[self closeProgressSheet];
	[self cancelWorkerThread];
	[self close];
}

- (void)closeProgressSheet
{
	if(progressWindowController != nil) {
        [[self windowForSheet] endSheet:[progressWindowController window] returnCode:NSModalResponseOK];
		[self removeWindowController:progressWindowController];
		[progressWindowController release];
		progressWindowController = nil;
	}
}

- (void)displayFileLoadingProgressSheet
{
    // This is just a helper for readFromURL. If the sheet is displayed within
    // readFromURL then weird glitches happen, so instead readFromURL queues
    // this method via a call to NSObject.performSelector.
    [self displayProgressSheetWithMessage:@"Loading" cancelSelector:@selector(cancelLoadingFile)];
}

- (void)displayProgressSheetWithMessage:(NSString *)message cancelSelector:(SEL)cancelSelector
{
    // The check for nil is to accomodate readFromURL, which has to delay displaying
    // the sheet. To avoid creating a race condition it creates the window controller
    // without a delay, so that the code that updates the progress bar doesn't need
    // to be aware of the delay.
	if(progressWindowController == nil)
		progressWindowController = [[PPProgressWindowController alloc] initWithLoadingMessage:message delegate:self cancelSelector:cancelSelector];

	[self addWindowController:progressWindowController];

    [[self windowForSheet]
        beginSheet:[progressWindowController window]
        completionHandler:nil];
}

- (void)displayFilterSheet
{
	PPCaptureFilterWindowController *filterWindowController;

	filterWindowController = [[PPCaptureFilterWindowController alloc] init];

	[self addWindowController:filterWindowController];

    [[self windowForSheet]
        beginSheet:[filterWindowController window]
        completionHandler:
            ^(NSModalResponse result)
            {
                [filterWindowController sheetDidEnd:[filterWindowController window] returnCode:result contextInfo:NULL];
            }];

	[filterWindowController release];
}

- (void)displaySetupSheet
{
	CaptureSetupWindowController *setupWindowController;

	setupWindowController = [[CaptureSetupWindowController alloc] init];

	[self addWindowController:setupWindowController];

    [[self windowForSheet]
        beginSheet:[setupWindowController window]
        completionHandler:
            ^(NSModalResponse result)
            {
                [setupWindowController sheetDidEnd:[setupWindowController window] returnCode:result contextInfo:NULL];
            }];

	[setupWindowController release];
}

- (void)displayIndividualWindow:(Packet *)aPacket
{
	IndividualPacketWindowController *controller;
	NSArray *controllersArray;
	unsigned int i;

	controllersArray = [self windowControllers];

	for(i = 0; i < [controllersArray count]; ++i) {
		controller = [controllersArray objectAtIndex:i];
		if([controller isMemberOfClass:[IndividualPacketWindowController class]] && [controller packet] == aPacket) {
			[controller showWindow:self];
			return;
		}
	}

	controller = [[IndividualPacketWindowController alloc] initWithPacket:aPacket];
	[self addWindowController:controller];
	[controller showWindow:self];
	[controller release];
}

- (void)displayReassemblyWindowForPacket:(Packet *)aPacket
{
	PPTCPStreamWindowController *controller;
	PPTCPStreamReassembler *reassembler;
	NSArray *controllersArray;
	unsigned int i;

	if(aPacket == nil || [aPacket decoderForClass:[IPV4Decode class]] == nil ||
	   [aPacket decoderForClass:[TCPDecode class]] == nil)
		return;

	controllersArray = [self windowControllers];

	if((reassembler = [[self tcpStreamController] streamReassemblerForPacket:aPacket]) == nil)
		return;

	for(i = 0; i < [controllersArray count]; ++i) {
		controller = [controllersArray objectAtIndex:i];
		if([controller isMemberOfClass:[PPTCPStreamWindowController class]] && [controller streamReassembler] == reassembler) {
			[controller showWindow:self];
			return;
		}
	}

	controller = [[PPTCPStreamWindowController alloc] initWithReassembler:reassembler];
	[reassembler addListener:controller];
	[self addWindowController:controller];
	[controller showWindow:self];
	[controller release];
}

- (void)displayStreamsWindow
{
	if(streamsWindowController == nil) {
		streamsWindowController = [[PPStreamsWindowController alloc] init];
		[self addWindowController:streamsWindowController];
	}

	[streamsWindowController showWindow:self];
}

- (void)displayArpSpoofingWindow
{
	if(arpSpoofingWindowController == nil) {
		arpSpoofingWindowController = [[PPArpSpoofingWindowController alloc] init];
		[self addWindowController:arpSpoofingWindowController];
	}
	[arpSpoofingWindowController showWindow:self];
}

- (void)removeWindowController:(NSWindowController *)windowController
{
	if([windowController isMemberOfClass:[PPStreamsWindowController class]])
		streamsWindowController = nil;

	[super removeWindowController:windowController];
}

- (PacketCaptureWindowController *)packetCaptureWindowController
{
	return captureWindowController;
}

- (BOOL)isLive
{
	return live;
}

- (void)setHostCache:(HostCache *)hostCache
{
	[hostCache retain];
	[hc release];
	hc = hostCache;
}

- (HostCache *)hostCache
{
	if(hc == nil)
		hc = [[HostCache sharedHostCache] retain];

	return hc;
}

- (NSString *)interface
{
	return interface;
}

- (void)setInterface:(NSString *)anInterface
{
	[anInterface retain];
	[interface release];
	interface = anInterface;
}

- (Packet *)packetAtIndex:(NSInteger)packetIndex
{
	NSUInteger total;

	total = [packets count];

	/* transform the index if we are in reverse order */
	if(reverseOrder)
		packetIndex = (total - 1) - packetIndex;

	if(packetIndex >= 0 && (NSUInteger)packetIndex < total)
		return [packets objectAtIndex:packetIndex];

	return nil;
}

- (size_t)numberOfPackets
{
	return [packets count];
}

- (size_t)numberOfBytes
{
	return byteCount;
}

- (void)updateControllers
{
	[captureWindowController update:NO];
	[streamsWindowController update:NO];
}

- (void)addPacketArray:(NSArray *)packetArray
{
	Packet *packet;
	unsigned int i;

	for(i = 0; i < [packetArray count]; ++i) {
		packet = [packetArray objectAtIndex:i];
		[packets addObject:packet];
		[streamController addPacket:packet];
		[packet setNumber:++packetCount];
		[packet setDocument:self];
		byteCount += [packet captureLength];
	}
	if(progressWindowController != nil)
		[progressWindowController setLoadingMessage:[NSString stringWithFormat:@"Loading, %lu packets", packetCount]];
}

- (void)addPacket:(Packet *)packet
{
	[packets addObject:packet];
	[streamController addPacket:packet];
	[packet setNumber:++packetCount];
	[packet setDocument:self];
	byteCount += [packet captureLength];
}

- (void)deletePacketAtIndex:(NSInteger)packetIndex
{
	/* transform the index if we are in reverse order */
	if(reverseOrder)
		packetIndex = ([packets count] - 1) - packetIndex;

	if(packetIndex >= 0 && (NSUInteger)packetIndex < [packets count]) {
		[streamController removePacket:[packets objectAtIndex:packetIndex]];
		byteCount -= [[packets objectAtIndex:packetIndex] captureLength];
		[packets removeObjectAtIndex:packetIndex];
		[self updateChangeCount:NSChangeDone];
	}
}

/* SLOW: do not call for deleting multiple packets! */
- (void)deletePacket:(Packet *)packet
{
	[self deletePacketAtIndex:[self indexForPacket:packet]];
}

/* Note: does *NOT* update the documents streamController */
- (void)purgePacketsPendingDeletionWithHint:(size_t)count
{
	Packet *packet;
	size_t i;

	i = 0;

	while(count > 0 && i < [packets count]) {
		packet = [packets objectAtIndex:i];

		if([packet isPendingDeletion]) {
			[packets removeObjectAtIndex:i];
			byteCount -= [[packets objectAtIndex:i] captureLength];
			--count;
		} else
			++i;
	}

	[self updateChangeCount:NSChangeDone];
}

- (void)deleteStream:(PPTCPStream *)stream streamIndex:(NSUInteger)streamIndex indexValid:(BOOL)indexValid
{
	size_t i;
	size_t count;

	count = [stream packetsCount];

	for(i = 0; i < count; ++i)
		[[stream packetAtIndex:i] setPendingDeletion];

	if(indexValid)
		[streamController removeStreamAtIndex:streamIndex];
	else
		[streamController removeStream:stream];

	[self purgePacketsPendingDeletionWithHint:count];
	/* purgePacketsPendingDeletion.. calls updateChangeCount */
}

- (void)deleteStream:(PPTCPStream *)stream streamIndex:(NSUInteger)streamIndex
{
	[self deleteStream:stream streamIndex:streamIndex indexValid:YES];
}

- (void)deleteStream:(PPTCPStream *)stream
{
	[self deleteStream:stream streamIndex:0 indexValid:NO];
}

- (NSArray *)packetsSortedByNumber
{
	if(allPackets != nil)
		return [allPackets sortedArrayUsingFunction:pkt_compare context:nil];

	return [packets sortedArrayUsingFunction:pkt_compare context:nil];
}

- (void)sortPacketsWithColumn:(ColumnIdentifier *)column
{
	[column retain];
	[sortColumn release];
	sortColumn = column;

	[packets sortUsingFunction:pkt_compare context:sortColumn];
}

- (void)setReversePacketOrder:(BOOL)reverse
{
	reverseOrder = reverse;
}

- (BOOL)isReverseOrder
{
	return reverseOrder;
}

- (NSInteger)indexForPacket:(Packet *)packet
{
	NSUInteger upper,
               lower,
               current,
               total;

	if(packet == nil)
		return -1;

	total = [packets count];

	upper = total - 1;
	lower = 0;

	for(;;) {
		current = (upper + lower) / 2;

		switch(pkt_compare([packets objectAtIndex:current], packet, sortColumn)) {
			/* current is greater */
			case NSOrderedDescending:
				if(upper == lower)
					return -1;
				upper = current;
				continue;
				/* NOTREACHED */

			/* current is smaller */
			case NSOrderedAscending:
				if(upper == lower)
					return -1;
				lower = current + 1;
				continue;
				/* NOTREACHED */

			case NSOrderedSame:
			default:
				/* pkt_compare may be inexact, so compare further */
				for(upper = current; [packets objectAtIndex:upper] != packet; ++upper) {
					if(upper == total - 1)
						return -1;

					if(pkt_compare([packets objectAtIndex:upper + 1], packet, sortColumn) != NSOrderedSame) {
						for(upper = current - 1; [packets objectAtIndex:upper] != packet; --upper) {
							if(upper == 0)
								return -1;
							if(pkt_compare([packets objectAtIndex:upper - 1], packet, sortColumn) != NSOrderedSame)
								return -1;
						}
						break;
					}
				}

				if(reverseOrder)
					upper = (total - 1) - upper;

				/* XXX - check upper fits into a signed int? */
				return upper;
				/* NOTREACHED */
		}
	}
	/* NOTREACHED */
}

- (PPTCPStreamController *)tcpStreamController
{
	return streamController;
}

/* display an error as a sheet and optionally close the document */
- (void)displayErrorStack:(ErrorStack *)errorStack close:(BOOL)closeDocument
{
	ErrorReportWindowController *errorReportWindowController;

	errorReportWindowController = [[ErrorReportWindowController alloc] init];
	[errorReportWindowController setErrorStack:errorStack];

    [[self windowForSheet]
        beginSheet:[errorReportWindowController window]
        completionHandler:
            ^(NSModalResponse result)
            {
                [self sheetDidEnd:[errorReportWindowController window]
                      returnCode:result
                      contextInfo:(void*)((intptr_t)closeDocument) /* disgust, intptr is to suppress warning... */];
            }];
}

- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(NSModalResponse)returnCode contextInfo:(void *)contextInfo
{
	if([[sheet windowController] isMemberOfClass:[ErrorReportWindowController class]])
    {
        [[sheet windowController] release];
        const BOOL closeDocument = (BOOL)contextInfo; /* disgust */
        if (closeDocument)
            [self close];
    }
}

- (void)startCaptureOn:(Interface *)anInterface
					   isPromiscuous:(BOOL)promiscuousVal
					   isRealTime:(BOOL)realTimeVal
					   bufferLength:(bufsize)bufferLengthVal
					   updateFrequency:(float)frequency
					   stopAfterPackets:(unsigned long)numberOfPackets
					   stopAfterDate:(NSDate *)stopDate
					   stopAfterData:(unsigned long long)numberOfBytes
					   stopAfterMatchAll:(BOOL)matchAllConditions
					   filter:(PPCaptureFilter *)filter
{
	MsgSettings *settings;
	CFSocketContext context;
	CFRunLoopSourceRef source;
	unsigned int real_buflen;

	endingPackets = numberOfPackets;
	endingBytes = numberOfBytes;
	endingMatchAll = matchAllConditions;

	if(stopDate != nil)
		endingTimer = [NSTimer scheduledTimerWithTimeInterval:[stopDate timeIntervalSinceNow] target:self selector:@selector(endCaptureWithTimer:) userInfo:nil repeats:NO];

	if(numberOfPackets > 0 || numberOfBytes > 0 || stopDate != nil)
		[captureWindowController cancelEndingButtonSetHidden:NO];

	[self setInterface:[anInterface shortName]];

	settings = nil;

	if((sockfd = [[MyDocumentController sharedDocumentController] launchHelper]) == -1)
		goto err;

	helperIO = [[ObjectIO alloc] initWithFileDescriptor:sockfd];

	switch(bufferLengthVal) {
		case BS_TINY:
			real_buflen = BPF_MINBUFSIZE;
			break;

		case BS_SMALL:
			real_buflen = BPF_SMALLBUFSIZE;	/* not a standard define */
			break;

		case BS_MEDIUM:
			real_buflen = BPF_MEDIUMBUFSIZE; /* not a standard define */
			break;

		case BS_LARGE:
			real_buflen = BPF_LARGEBUFSIZE; /* not a standard define */
			break;

		case BS_HUGE:
		default:
			real_buflen = BPF_MAXBUFSIZE;
	}

	settings = [[MsgSettings alloc] initWithInterface:interface
				bufLength:real_buflen
				timeout:NULL
				promiscuous:promiscuousVal
				immediate:realTimeVal
				filterProgram:[filter filterProgramForLinkType:[anInterface linkType]]];

	if([helperIO write:settings] == -1)
		goto err;

	context.version = 0;
	context.info = self;
	context.retain = NULL;
	context.release = NULL;
	context.copyDescription = NULL;

	if((sockref = CFSocketCreateWithNative(kCFAllocatorDefault, sockfd, kCFSocketReadCallBack, socketCallBack, &context)) == NULL) {
		[[ErrorStack sharedErrorStack] pushError:@"Call to CFSocketCreateWithNative failed" lookup:Nil code:0 severity:ERRS_ERROR];
		goto err;
	}

	if((source = CFSocketCreateRunLoopSource(kCFAllocatorDefault, sockref, 0)) == NULL) {
		[[ErrorStack sharedErrorStack] pushError:@"Call to CFSocketCreateRunLoopSource failed" lookup:Nil code:0 severity:ERRS_ERROR];
		goto err;
	}

	CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);

	live = YES;
	linkType = [anInterface linkType];
	[settings release];
	[captureWindowController synchronizeWindowTitleWithDocumentName];
	[captureWindowController update:NO];
	return;

	err:
		if(settings)
			[settings release];
		[self stopCapture];
		[self displayErrorStack:nil close:YES];
}

- (void)flushHostnames
{
	if(hc != nil) {
		[hc flush];
		[self updateChangeCount:NSChangeDone];
	}
}

- (void)stopCapture
{
	if(live) {
		if(sockref != NULL) {
			/* invalidating the socket also invalidates the run loop source, so the callback is disabled */
			CFSocketInvalidate(sockref);
			CFRelease(sockref);
			sockref = NULL;
		}
		if(helperIO != nil) {
			[helperIO write:[[[MsgQuit alloc] init] autorelease]];
			[helperIO release];
			helperIO = nil;
		}
		if(sockfd != -1) {
			(void)close(sockfd);
			sockfd = -1;
		}
		live = NO;
		[captureWindowController update:NO];
		[captureWindowController cancelEndingButtonSetHidden:YES];
		[self cancelEndingConditions];
	}
}

- (void)updateControllerWithTimer:(NSTimer *)aTimer
{
	[captureWindowController updateWithUserScrolling];
	[streamsWindowController updateWithUserScrolling];
}

- (void)endCaptureWithTimer:(NSTimer *)aTimer
{
	endingTimer = nil;
	if(!endingMatchAll || (endingPackets == 0 && endingBytes == 0))
		[self stopCapture];
}

- (void)cancelEndingConditions
{
	if(endingTimer != nil)
		[endingTimer invalidate];
	endingPackets = 0;
	endingBytes = 0;
}

- (void)readData
{
	id obj;

	do {
		if((obj = [helperIO read]) == nil)
			goto err;

		if([obj isMemberOfClass:[Packet class]]) {
			[(Packet *)obj setNumber:++packetCount];
			[(Packet *)obj setDocument:self];

			[allPackets addObject:obj];

			if(bpfProgram == nil || [(Packet *)obj runFilterProgram:bpfProgram]) {
				[packets addObject:obj];
				byteCount += [(Packet *)obj captureLength];
			}

			[streamController addPacket:obj];

			if(endingBytes > 0) {
				if(endingBytes <= [obj actualLength]) {
					endingBytes = 0;
					if(!endingMatchAll || (endingPackets == 0 && endingTimer != nil))
						[self stopCapture];
				} else
					endingBytes -= [obj actualLength];
			}
			if(endingPackets > 0 && packetCount >= endingPackets) {
				if(!endingMatchAll || (endingBytes == 0 && endingTimer != nil))
					[self stopCapture];
			}
		} else {
			/* if we got some unknown object, push an error */
			if(![obj isMemberOfClass:[ErrorStack class]]) {
				[[ErrorStack sharedErrorStack] pushError:@"Received unknown object from helper tool" lookup:Nil code:0 severity:ERRS_ERROR];
				obj = nil;
			}
			goto err;
		}
	} while([helperIO moreAvailable]);

	if(timer == nil || ![timer isValid]) {
		[timer release];
		timer = [[NSTimer scheduledTimerWithTimeInterval:DEFAULT_UI_UPDATE_FREQUENCY target:self selector:@selector(updateControllerWithTimer:) userInfo:nil repeats:NO] retain];
	}

	[self updateChangeCount:NSChangeDone];
	return;

	err:
		[self stopCapture];
		[self displayErrorStack:obj close:([packets count] == 0) ? YES : NO]; /* close if no packets received */
}

- (void)clearFilterProgram:(BOOL)discardFilteredPackets
{
	if(allPackets != nil) {
		if(discardFilteredPackets) {
			[allPackets release];
			allPackets = nil;

			[bpfProgram release];
			bpfProgram = nil;

			[self updateChangeCount:NSChangeDone];
		} else {
			[packets release];
			packets = allPackets;
			allPackets = nil;

			[bpfProgram release];
			bpfProgram = nil;

			[streamController flush];
			[streamController addPacketArray:packets];

			[self updateControllers];
		}
	}
}

- (PPBPFProgram *)filterProgram
{
	return bpfProgram;
}

- (void)setCaptureFilter:(PPCaptureFilter *)captureFilter
{
	int ret;

	if(captureFilter == nil)
		return;

	if(thread_args != NULL) {
		[[ErrorStack sharedErrorStack] pushError:@"File loading or saving operation already in progress" lookup:Nil code:errno severity:ERRS_ERROR];
		goto err;
	}

	if(allPackets == nil)
		allPackets = [[NSMutableArray alloc] initWithArray:packets];

	if(!live && [allPackets count] < 1)
		return;

	if((thread_args = malloc(sizeof(struct thread_args))) == NULL) {
		[[ErrorStack sharedErrorStack] pushError:@"Failed to allocate memory" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
		goto err;
	}

	[bpfProgram release];
	bpfProgram = [[captureFilter filterProgramForLinkType:[self linkType]] retain];

	/* due to back pointers in TCPDecode->PPTCPStream, we can't maintain two stream controllers, because
	   when the first one is released the back pointers will be incorrectly cleared, or if the user cancels */
	[streamController release];
	streamController = nil;

	[self displayProgressSheetWithMessage:@"Filtering" cancelSelector:@selector(cancelCaptureFilterExecution)];

	thread_args->op = THREAD_OP_DOC_FILTER;
	thread_args->input[0] = [[NSArray alloc] initWithArray:allPackets];
	thread_args->input[1] = [bpfProgram retain]; /* this is kind of lame, as we've already retained above, but
													it allows workerThreadTimer to be generic (in that it releases
													thread inputs after the thread is done) */
	thread_args->input[2] = nil;
	thread_args->output[0] = nil;
	thread_args->output[1] = nil;
	thread_args->cancel = 0;
	thread_args->failure = 0;
	thread_args->success = 0;
	thread_args->units_current = 0;
	thread_args->units_total = 0;

	if((ret = pthread_create(&thread_args->thread_id, NULL, filter_packets_thread, thread_args)) != 0) {
		[[ErrorStack sharedErrorStack] pushError:@"Failed to create thread" lookup:[PosixError class] code:ret severity:ERRS_ERROR];
		[thread_args->input[0] release];
		[thread_args->input[1] release];
		free(thread_args);
		thread_args = NULL;
	}

	thread_args->timer = [[NSTimer scheduledTimerWithTimeInterval:DEFAULT_PROGRESSBAR_UPDATE_FREQUENCY target:self selector:@selector(workerThreadTimer) userInfo:nil repeats:YES] retain];

	return;

err:
	[self closeProgressSheet];
	[self displayErrorStack:nil close:NO];
}

- (void)dealloc
{
	[timer release];
	[self cancelWorkerThread];
	[self stopCapture];
	[sortColumn release];
	[bpfProgram release];
	[progressWindowController release];
	[captureWindowController release];
	[streamsWindowController release];
	[helperIO release];
	[streamController release];
	[allPackets release];
	[packets release];
	[hc release];
	[interface release];
	[super dealloc];
}

@end

static void socketCallBack(CFSocketRef s, CFSocketCallBackType callbackType, CFDataRef address, const void *data, void *info)
{
	[(MyDocument *)info readData];
}

static void *read_from_url_thread(void *args)
{
	NSAutoreleasePool *autoreleasePool;
	NSMutableArray *packetArray;
	PPTCPStreamController *streamController;
	pcap_t *pcap;
	const uint8_t *bytes;
	struct pcap_pkthdr *hdr;
	struct thread_args *thread_args;
	FILE *fp;
	Class linkType;
	size_t nbytes;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct stat sb;
	unsigned int packet_number;
	int fd;
	int ret;

	pcap = NULL;
	thread_args = args;

	autoreleasePool = [[NSAutoreleasePool alloc] init];
	packetArray = [[NSMutableArray alloc] init];
	streamController = [[PPTCPStreamController alloc] init];

	if((pcap = pcap_open_offline([[(NSURL *)thread_args->input[0] path] UTF8String], errbuf)) == NULL) {
		thread_args->output[0] = [[NSString alloc] initWithUTF8String:errbuf];
		goto err;
	}

	if((linkType = dlt_lookup(pcap_datalink(pcap))) == Nil) {
		thread_args->output[0] = @"Unsupported link-layer";
		goto err;
	}

	if((fp = pcap_file(pcap)) != NULL && (fd = fileno(fp)) != -1 && fstat(fd, &sb) == 0)
		thread_args->units_total = sb.st_size - sizeof(struct pcap_file_header);

	thread_args->output[0] = nil;
	thread_args->output[1] = nil;
	nbytes = 0;

	for(packet_number = 1; (ret = pcap_next_ex(pcap, &hdr, &bytes)) == 1; ++packet_number) {
		NSData *data;
		Packet *packet;

		data = [[NSData alloc] initWithBytes:bytes length:hdr->caplen];
		packet = [[Packet alloc] initWithData:data captureLength:hdr->caplen actualLength:hdr->len timestamp:TIMEVAL_TO_NSDATE(hdr->ts) linkLayer:linkType];

		[packet setNumber:packet_number];
		nbytes += [packet captureLength];

		[packetArray addObject:packet];
		[streamController addPacket:packet];

		[packet release];
		[data release];

		thread_args->units_current += hdr->caplen + sizeof(struct pcap_pkthdr);

		/* user cancelled file loading */
		if(thread_args->cancel != 0) {
			[packetArray release];
			[streamController release];
			goto cleanup;
		}
	}

	if(ret != -2 && packet_number == 1) {
		thread_args->output[0] = @"Error reading packet";
		goto err;
	}

	/* the document is responsible for releasing thread_args->output */
	thread_args->output[0] = packetArray;
	thread_args->output[1] = streamController;
	thread_args->nbytes = nbytes;

	OSMemoryBarrier();
	thread_args->success = 1;

cleanup:
	[autoreleasePool release];
	pcap_close(pcap);

	return thread_args->output[0];

err:
	[packetArray release];
	[streamController release];
	[autoreleasePool release];

	if(pcap != NULL)
		pcap_close(pcap);

	/* the document is responsible for releasing thread_args->output */

	OSMemoryBarrier();
	thread_args->failure = 1;

	return thread_args->output[0];
}

static void *filter_packets_thread(void *args)
{
	NSAutoreleasePool *autoreleasePool;
	NSMutableArray *filteredPackets;
	NSArray *tempPackets;
	PPTCPStreamController *streamController;
	struct thread_args *thread_args;
	unsigned int i;

	thread_args = args;

	autoreleasePool = [[NSAutoreleasePool alloc] init];
	filteredPackets = [[NSMutableArray alloc] init];

	thread_args->units_total = [(NSArray *)thread_args->input[0] count];
	thread_args->output[0] = nil;
	thread_args->output[1] = nil;

	for(thread_args->units_current = 0; thread_args->units_current < thread_args->units_total; ++thread_args->units_current) {
		Packet *packet;

		packet = [(NSArray *)thread_args->input[0] objectAtIndex:thread_args->units_current];

		if([packet runFilterProgram:(PPBPFProgram *)thread_args->input[1]])
			[filteredPackets addObject:packet];

		if(thread_args->cancel != 0) {
			[filteredPackets release];
			goto cleanup;
		}
	}

	streamController = [[PPTCPStreamController alloc] init];
	tempPackets = [filteredPackets sortedArrayUsingFunction:pkt_compare context:nil];

	for(i = 0; i < [tempPackets count]; ++i) {
		[streamController addPacket:[tempPackets objectAtIndex:i]];

		if(thread_args->cancel != 0) {
			[filteredPackets release];
			[streamController release];
			goto cleanup;
		}
	}

	/* the document is responsible for releasing thread_args->output */
	thread_args->output[0] = filteredPackets;
	thread_args->output[1] = streamController;

	OSMemoryBarrier();
	thread_args->success = 1;

cleanup:
	[autoreleasePool release];
	return thread_args->output[0];
}

