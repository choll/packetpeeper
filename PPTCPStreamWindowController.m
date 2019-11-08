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

#include "PPTCPStreamWindowController.h"
#include "HostCache.hh"
#include "MyDocument.h"
#include "PPTCPStream.h"
#include "PPTCPStreamReassembler.h"
#include "PacketCaptureWindowController.h"
#include "PacketPeeper.h"
#import <AppKit/NSColor.h>
#import <AppKit/NSFont.h>
#import <AppKit/NSLayoutManager.h>
#import <AppKit/NSResponder.h>
#import <AppKit/NSScrollView.h>
#import <AppKit/NSTextContainer.h>
#import <AppKit/NSTextStorage.h>
#import <AppKit/NSTextView.h>
#import <AppKit/NSWindow.h>
#import <Foundation/NSAttributedString.h>
#import <Foundation/NSData.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSString.h>
#include <ctype.h>
#include <float.h>
#include <sys/types.h>

#define byte_to_printable(x) \
    (((x) != '\n' && (x) != '\r' && ((x) < 0x20 || (x) > 0x7e)) ? '.' : (x))

@interface NSMutableAttributedString (PPMutableAttributedStringAdditions)

- (unichar)characterAtIndex:(unsigned)index;
- (unsigned int)length;
- (const char*)cStringUsingEncoding:(NSStringEncoding)encoding;

@end

@interface PPTextStorage : NSTextStorage
{
    NSMutableAttributedString* m_string;
}

- (NSString*)string;
- (NSDictionary*)attributesAtIndex:(unsigned int)index
                    effectiveRange:(NSRangePointer)aRange;
- (void)replaceCharactersInRange:(NSRange)aRange withString:(NSString*)aString;
- (void)setAttributes:(NSDictionary*)attributes range:(NSRange)aRange;

@end

@implementation PPTextStorage

- (id)init
{
    if ((self = [super init]) != nil)
    {
        m_string = [[NSMutableAttributedString alloc] init];
    }
    return self;
}

- (NSString*)string
{
    return [m_string string];
}

- (NSMutableString*)mutableString
{
    return [m_string mutableString];
}

- (NSDictionary*)attributesAtIndex:(unsigned)attributeIndex
                    effectiveRange:(NSRangePointer)aRange
{
    return [m_string attributesAtIndex:attributeIndex effectiveRange:aRange];
}

- (void)replaceCharactersInRange:(NSRange)aRange withString:(NSString*)aString
{
    [m_string replaceCharactersInRange:aRange withString:aString];
    [self edited:NSTextStorageEditedCharacters
                 range:aRange
        changeInLength:[aString length] - aRange.length];
}

- (void)setAttributes:(NSDictionary*)attributes range:(NSRange)aRange
{
    [m_string setAttributes:attributes range:aRange];
    [self edited:NSTextStorageEditedAttributes range:aRange changeInLength:0];
}

- (void)dealloc
{
    [m_string release];
    [super dealloc];
}

@end

@implementation PPTCPStreamWindowController

- (id)initWithReassembler:(PPTCPStreamReassembler*)aReassembler
{
    if ((self = [super initWithWindowNibName:@"PPTCPStreamWindow"]) != nil)
    {
        textView = nil;
        reassembler = [aReassembler retain];
        lastChunk = 0;
        lastLocation = 0;
    }
    return self;
}

- (void)windowDidLoad
{
    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(hostNameLookupCompletedNotification:)
               name:PPHostCacheHostNameLookupCompleteNotification
             object:[[self document] hostCache]];

    PPTextStorage* textStorage;
    NSLayoutManager* layoutManager;
    NSTextContainer* textContainer;
    NSScrollView* scrollView;
    NSRect frame;
    NSSize contentSize;

    frame = [[[self window] contentView] frame];

    textStorage = [[PPTextStorage alloc] init];

    layoutManager = [[NSLayoutManager alloc] init];
    [textStorage addLayoutManager:layoutManager];

    textContainer = [[NSTextContainer alloc] initWithContainerSize:frame.size];
    [layoutManager addTextContainer:textContainer];

    scrollView = [[NSScrollView alloc] initWithFrame:frame];
    contentSize = [scrollView contentSize];

    [scrollView setBorderType:NSNoBorder];
    [scrollView setHasVerticalScroller:YES];
    [scrollView setHasHorizontalScroller:YES];
#ifdef __APPLE__
    [scrollView setAutohidesScrollers:NO];
#endif
    [scrollView setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];

    textView = [[NSTextView alloc]
        initWithFrame:NSMakeRect(0, 0, contentSize.width, contentSize.height)
        textContainer:textContainer];

    [textView setMinSize:NSMakeSize(0.0, contentSize.height)];
    [textView setMaxSize:NSMakeSize(FLT_MAX, FLT_MAX)];
    [textView setHorizontallyResizable:YES];
    [textView setVerticallyResizable:YES];
    [textView setAutoresizingMask:NSViewNotSizable];

    [textView setAllowsUndo:NO];
    [textView setContinuousSpellCheckingEnabled:NO];
    [textView setEditable:NO];
    [textView setRichText:NO];
    [textView setUsesFontPanel:NO];
    [textView setSelectable:YES];

    [textContainer setContainerSize:NSMakeSize(FLT_MAX, FLT_MAX)];
    [textContainer setWidthTracksTextView:NO];
    [textContainer setHeightTracksTextView:NO];

    [scrollView setDocumentView:textView];
    [[self window] setContentView:scrollView];
    [[self window] makeKeyAndOrderFront:nil];
    [[self window] makeFirstResponder:textView];

    [textView setFont:[NSFont userFixedPitchFontOfSize:0.0f]];

    [layoutManager release];
    [textContainer release];
    [scrollView release];
    [textView release];

    [self processStreamData];
}

- (NSString*)windowTitleForDocumentDisplayName:(NSString*)displayName
{
    PPTCPStream* stream;

    stream = [reassembler stream];

    return [NSString stringWithFormat:@"%@ - %@ - %@:%u -> %@:%u",
                                      displayName,
                                      [[self document] interface],
                                      [stream hostFrom],
                                      [stream srcPort],
                                      [stream hostTo],
                                      [stream dstPort]];
}

- (void)setDocumentEdited:(BOOL)flag
{
    return;
}

- (NSResponder*)nextResponder
{
    return [[self document] packetCaptureWindowController];
}

- (void)hostNameLookupCompletedNotification:(NSNotification*)note
{
    [self synchronizeWindowTitleWithDocumentName];
}

- (void)reset
{
    NSRange range;

    lastChunk = 0;
    lastLocation = 0;

    range.length = [[[textView layoutManager] textStorage] length];
    range.location = 0;

    [[[textView layoutManager] textStorage] deleteCharactersInRange:range];
}

- (void)processStreamData
{
    [reassembler reassemble];
    [self processStreamDataFromChunk:0];
}

- (void)processStreamDataFromChunk:(unsigned int)chunk
{
    NSMutableAttributedString* mutableAttributedString;
    NSDictionary* redAttributes;
    NSDictionary* blueAttributes;
    id objects[2];
    id keys[2];

    keys[0] = NSForegroundColorAttributeName;
    keys[1] = NSFontAttributeName;

    objects[1] = [NSFont userFixedPitchFontOfSize:0.0f];

    objects[0] = [NSColor redColor];
    redAttributes = [[NSDictionary alloc] initWithObjects:objects
                                                  forKeys:keys
                                                    count:ARRAY_NELEMS(keys)];

    objects[0] = [NSColor blueColor];
    blueAttributes = [[NSDictionary alloc] initWithObjects:objects
                                                   forKeys:keys
                                                     count:ARRAY_NELEMS(keys)];

    mutableAttributedString = [[NSMutableAttributedString alloc] init];

    for (; chunk < [reassembler numberOfChunks]; ++chunk)
    {
        NSString* tempString;
        NSAttributedString* tempAttributedString;

        uint8_t* temp;
        const uint8_t* chunk_bytes;

        size_t nbytes;
        size_t nbytes_w;
        size_t i;

        nbytes = [[reassembler chunkDataAt:chunk] length];
        chunk_bytes = [[reassembler chunkDataAt:chunk] bytes];

        if ((temp = malloc(nbytes)) == NULL)
            break;

        nbytes_w = nbytes - (nbytes % 4);

        for (i = 0; i < nbytes_w; i += 4)
        {
            temp[i] = byte_to_printable(chunk_bytes[i]);
            temp[i + 1] = byte_to_printable(chunk_bytes[i + 1]);
            temp[i + 2] = byte_to_printable(chunk_bytes[i + 2]);
            temp[i + 3] = byte_to_printable(chunk_bytes[i + 3]);
        }

        for (; i < nbytes; ++i)
            temp[i] = byte_to_printable(chunk_bytes[i]);

        tempString = [[NSString alloc]
            initWithBytesNoCopy:temp
                         length:[[reassembler chunkDataAt:chunk] length]
                       encoding:NSASCIIStringEncoding
                   freeWhenDone:YES];

        tempAttributedString = [[NSAttributedString alloc]
            initWithString:tempString
                attributes:([reassembler chunkIsClient:chunk])
                               ? redAttributes
                               : blueAttributes];
        [mutableAttributedString appendAttributedString:tempAttributedString];

        [tempString release];
        [tempAttributedString release];
    }

    [[textView textStorage] appendAttributedString:mutableAttributedString];
    [mutableAttributedString release];
    lastChunk = chunk;
}

- (void)noteChunksDeleted
{
    [self reset];
    [self processStreamData];
}

- (void)noteChunksAppended
{
    /* TODO; give the user an option to make the NSTextView auto-scroll on new input,
	   probably making the packet list auto-scroll a generic option */
    [self processStreamDataFromChunk:lastChunk];
}

- (PPTCPStreamReassembler*)streamReassembler
{
    return reassembler;
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [reassembler removeListener:self];
    [reassembler release];
    [super dealloc];
}

@end
