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

#include "PPStreamsWindowController.h"
#include "../../AppController.h"
#include "../ColumnIdentifier.h"
#include "../../Categories/DateFormat.h"
#include "../../HostCache.hh"
#include "../MyDocument.h"
#include "../PPDataQuantityFormatter.h"
#include "../PPPacketUIAdditions.h"
#include "../../TCPStreams/PPTCPStream.h"
#include "../../TCPStreams/PPTCPStreamController.h"
#include "../../../Shared/Decoding/Packet.h"
#include "../PacketCaptureWindowController.h"
#include "../../../Shared/PacketPeeper.h"
#include "../../../Shared/Decoding/TCPDecode.h"
#include "../syncmenu.h"
#import <AppKit/NSApplication.h>
#import <AppKit/NSCell.h>
#import <AppKit/NSImage.h>
#import <AppKit/NSMenu.h>
#import <AppKit/NSTableColumn.h>
#import <AppKit/NSTableHeaderCell.h>
#import <AppKit/NSTextFieldCell.h>
#import <AppKit/NSWindow.h>
#import <Appkit/NSColor.h>
#import <Foundation/NSArchiver.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSDate.h>
#import <Foundation/NSIndexSet.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSString.h>
#import <Foundation/NSUserDefaults.h>

@implementation PPStreamsWindowController

+ (NSMenu*)createStreamTableMenu
{
    NSMenu* menu;
    NSMenuItem* item;
    unsigned int i;
    NSString* representedObjects[] = {
        PPSTREAMSWINDOW_STREAMS_TABLE_SRC_IP_ADDRESS,
        PPSTREAMSWINDOW_STREAMS_TABLE_DST_IP_ADDRESS,
        PPSTREAMSWINDOW_STREAMS_TABLE_SRC_HOSTNAME,
        PPSTREAMSWINDOW_STREAMS_TABLE_DST_HOSTNAME,
        PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORT,
        PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORT,
        PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORTNAME,
        PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORTNAME,
        PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_SENT,
        PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_RECV,
        PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_TOTAL,
        PPSTREAMSWINDOW_STREAMS_TABLE_STATUS};
    NSString* titles[] = {@"Source IP Address",
                          @"Destination IP Address",
                          @"Source Hostname",
                          @"Destination Hostname",
                          @"Source Port",
                          @"Destination Port",
                          @"Source Port Name",
                          @"Destination Port Name",
                          @"Bytes Sent",
                          @"Bytes Received",
                          @"Bytes Total",
                          @"Status"};

    menu = [[NSMenu alloc] init];

    for (i = 0; i < (sizeof(titles) / sizeof(titles[0])); ++i)
    {
        item = [[NSMenuItem alloc] init];
        [item setTitle:titles[i]];
        [item setRepresentedObject:representedObjects[i]];
        [item setAction:@selector(columnMenuAction:)];
        [menu addItem:item];
        [item release];
    }

    return [menu autorelease];
}

- (id)init
{
    if ((self = [super initWithWindowNibName:@"PPStreamsWindow"]) != nil)
    {
        selectedStream = nil;
        lastPacketTableColumn = nil;
        lastStreamTableColumn = nil;
    }
    return self;
}

- (void)windowDidLoad
{
    autoScrolling = [[NSUserDefaults standardUserDefaults]
        boolForKey:PPSTREAMSWINDOW_AUTOSCROLLING];

    [streamTableView setDataSource:self];
    [packetTableView setDataSource:self];
    [streamTableView setDelegate:self];
    [packetTableView setDelegate:self];
    [streamTableView setDoubleAction:@selector(doubleAction:)];
    [packetTableView setDoubleAction:@selector(doubleAction:)];

    [streamTableView
        setColumnAutoresizingStyle:NSTableViewNoColumnAutoresizing];
    [packetTableView
        setColumnAutoresizingStyle:NSTableViewNoColumnAutoresizing];

    [[packetTableView headerView]
        setMenu:[(AppController*)[NSApp delegate] createTCPProtocolsMenu]];
    [[streamTableView headerView]
        setMenu:[PPStreamsWindowController createStreamTableMenu]];

    [self populateStreamTableView];
    [self populatePacketTableView];

    syncMenu(
        [self packetTableColumnMenu],
        [self packetTableColumnIdentifierStrings]);
    syncMenu(
        [self streamTableColumnMenu],
        [self streamTableColumnIdentifierStrings]);

    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(hostNameLookupCompletedNotification:)
               name:PPHostCacheHostNameLookupCompleteNotification
             object:[[self document] hostCache]];
}

- (void)hostNameLookupCompletedNotification:(NSNotification*)note
{
    [streamTableView reloadData];
    [packetTableView reloadData];
}

- (void)populatePacketTableView
{
    NSData* arrayAsData;
    NSArray* columns;
    unsigned int i;

    if ((arrayAsData = [[NSUserDefaults standardUserDefaults]
             objectForKey:PPSTREAMSWINDOW_PACKETTABLEVIEW_COLUMNS_KEY]) == nil)
        return;

    if ((columns = [NSUnarchiver unarchiveObjectWithData:arrayAsData]) == nil)
        return;

    for (i = 0; i < [columns count]; ++i)
        [packetTableView addTableColumn:[columns objectAtIndex:i]];
}

- (void)populateStreamTableView
{
    NSData* arrayAsData;
    NSArray* columns;
    unsigned int i;

    if ((arrayAsData = [[NSUserDefaults standardUserDefaults]
             objectForKey:PPSTREAMSWINDOW_STREAMTABLEVIEW_COLUMNS_KEY]) == nil)
        return;

    if ((columns = [NSUnarchiver unarchiveObjectWithData:arrayAsData]) == nil)
        return;

    for (i = 0; i < [columns count]; ++i)
        [streamTableView addTableColumn:[columns objectAtIndex:i]];
}

- (void)doubleAction:(id)sender
{
    NSInteger row;

    if ((row = [sender clickedRow]) == -1)
        return;

    if (sender == packetTableView)
        [[self document]
            displayIndividualWindow:[selectedStream packetAtIndex:row]];

    if (sender == streamTableView)
        [[self document]
            displayReassemblyWindowForPacket:[[[[self document]
                                                 tcpStreamController]
                                                 streamAtIndex:row]
                                                 packetAtIndex:0]];
}

- (IBAction)columnMenuAction:(id)sender
{
    NSTableColumn* column;
    NSTableView* tableView;
    id identifier;

    identifier = [sender representedObject];

    if ([sender menu] == [self streamTableColumnMenu])
        tableView = streamTableView;
    else
        tableView = packetTableView;

    if ([sender state] == NSOffState)
    {
        column = [[NSTableColumn alloc] initWithIdentifier:identifier];

        if ([identifier isMemberOfClass:[ColumnIdentifier class]])
            [[column headerCell] setStringValue:[identifier shortName]];
        else if ([identifier isKindOfClass:[NSString class]])
            [[column headerCell] setStringValue:[sender title]];
        else
            return;

        [column setEditable:NO];
        [tableView addTableColumn:column];
        [column release];
        [sender setState:NSOnState];
    }
    else if ([tableView numberOfColumns] > 1)
    { /* the user must have at least one column */
        [tableView
            removeTableColumn:[tableView tableColumnWithIdentifier:
                                             [sender representedObject]]];
        [sender setState:NSOffState];
    }

    if (tableView == streamTableView)
        [self saveStreamTableViewColumns];

    if (tableView == packetTableView)
        [self savePacketTableViewColumns];
}

- (void)savePacketTableViewColumns
{
    NSData* data;

    data =
        [NSArchiver archivedDataWithRootObject:[packetTableView tableColumns]];

    [[NSUserDefaults standardUserDefaults]
        setObject:data
           forKey:PPSTREAMSWINDOW_PACKETTABLEVIEW_COLUMNS_KEY];
}

- (void)saveStreamTableViewColumns
{
    NSData* data;

    data =
        [NSArchiver archivedDataWithRootObject:[streamTableView tableColumns]];

    [[NSUserDefaults standardUserDefaults]
        setObject:data
           forKey:PPSTREAMSWINDOW_STREAMTABLEVIEW_COLUMNS_KEY];
}

/* used to sync up the table columns and table menu */
- (NSMutableArray*)tableColumnIdentifierStringsForTableColumns:
    (NSArray*)tableColumns
{
    NSMutableArray* ret;
    unsigned int i;

    ret = [[NSMutableArray alloc] initWithCapacity:[tableColumns count]];

    for (i = 0; i < [tableColumns count]; ++i)
        [ret addObject:[[tableColumns objectAtIndex:i] identifier]];

    return [ret autorelease];
}

- (NSMutableArray*)packetTableColumnIdentifierStrings
{
    return [self tableColumnIdentifierStringsForTableColumns:[packetTableView
                                                                 tableColumns]];
}

- (NSMutableArray*)streamTableColumnIdentifierStrings
{
    return [self tableColumnIdentifierStringsForTableColumns:[streamTableView
                                                                 tableColumns]];
}

- (NSMenu*)packetTableColumnMenu
{
    return [[packetTableView headerView] menu];
}

- (NSMenu*)streamTableColumnMenu
{
    return [[streamTableView headerView] menu];
}

- (NSString*)windowTitleForDocumentDisplayName:(NSString*)displayName
{
    return [NSString stringWithFormat:@"%@ - %@ - TCP Streams",
                                      displayName,
                                      [[self document] interface]];
}

- (void)setDocumentEdited:(BOOL)flag
{
    return;
}

- (NSResponder*)nextResponder
{
    return [[self document] packetCaptureWindowController];
}

- (NSInteger)numberOfRowsInPacketTableView
{
    if (selectedStream != nil)
        return [selectedStream packetsCount];

    return 0;
}

- (NSInteger)numberOfRowsInStreamTableView
{
    return [[[self document] tcpStreamController] numberOfStreams];
}

- (id)packetTableObjectValueForTableColumn:(NSTableColumn*)tableColumn
                                       row:(NSInteger)rowIndex
{
    if (rowIndex < 0)
        return nil;

        // XXX WONTFIX
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
    return [[selectedStream packetAtIndex:rowIndex]
        stringForColumn:[tableColumn identifier]];
#pragma clang diagnostic pop
}

- (id)streamTableObjectValueForTableColumn:(NSTableColumn*)tableColumn
                                       row:(NSInteger)rowIndex
{
    PPTCPStream* stream;

    if (rowIndex < 0)
        return nil;

    stream = [[[self document] tcpStreamController] streamAtIndex:rowIndex];

    if ([[tableColumn identifier]
            isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_SRC_IP_ADDRESS])
    {
        return [stream addrFrom];
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_DST_IP_ADDRESS])
    {
        return [stream addrTo];
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_SRC_HOSTNAME])
    {
        return [stream hostFrom];
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_DST_HOSTNAME])
    {
        return [stream hostTo];
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORT])
    {
        return [NSString stringWithFormat:@"%u", [stream srcPort]];
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORT])
    {
        return [NSString stringWithFormat:@"%u", [stream dstPort]];
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORTNAME])
    {
        return [stream srcPortName];
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORTNAME])
    {
        return [stream dstPortName];
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_SENT])
    {
        return data_quantity_str([stream bytesSent]);
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_RECV])
    {
        return data_quantity_str([stream bytesReceived]);
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_TOTAL])
    {
        return data_quantity_str([stream totalBytes]);
    }
    else if ([[tableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_STATUS])
    {
        return [stream status];
    }

    return nil;
}

- (void)streamTableDidClickTableColumn:(NSTableColumn*)tableColumn
{
    NSMutableIndexSet* mutableIndexSet;
    NSIndexSet* indexSet;
    NSRange range;
    NSUInteger indexes[128];
    size_t i, n;

    mutableIndexSet = nil;

    if (lastStreamTableColumn == tableColumn)
    {
        size_t n_streams;

        /* same column clicked, so reverse the sort order */
        if ((mutableIndexSet = [[NSMutableIndexSet alloc] init]) == nil)
            return;

        indexSet = [streamTableView selectedRowIndexes];
        n_streams = [[[self document] tcpStreamController] numberOfStreams];

        range.location = [indexSet firstIndex];
        range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

        /* reverse each index in the set */
        while ((n = [indexSet getIndexes:indexes
                                maxCount:(sizeof(indexes) / sizeof(indexes[0]))
                            inIndexRange:&range]) > 0)
        {
            for (i = 0; i < n; ++i)
            {
                [mutableIndexSet addIndex:(n_streams - indexes[i]) - 1];
            }
        }

        [[[self document] tcpStreamController]
            setReversePacketOrder:![[[self document] tcpStreamController]
                                      isReverseOrder]];
    }
    else
    {
        NSMutableArray* streams;

        /* different column clicked, sort normally */
        [[[self document] tcpStreamController] setReversePacketOrder:NO];

        if (lastStreamTableColumn != nil)
        {
            [streamTableView setIndicatorImage:nil
                                 inTableColumn:lastStreamTableColumn];
            [lastStreamTableColumn release];
        }

        lastStreamTableColumn = [tableColumn retain];
        [streamTableView setHighlightedTableColumn:tableColumn];

        if ((streams = [[NSMutableArray alloc] init]) != nil)
        {
            indexSet = [streamTableView selectedRowIndexes];
            range.location = [indexSet firstIndex];
            range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

            while (
                (n = [indexSet getIndexes:indexes
                                 maxCount:(sizeof(indexes) / sizeof(indexes[0]))
                             inIndexRange:&range]) > 0)
            {
                for (i = 0; i < n; ++i)
                    [streams addObject:[[[self document] tcpStreamController]
                                           streamAtIndex:indexes[i]]];
            }
        }

        [self sortStreamTable];

        n = [streams count];

        if (n > 0 && streams != nil &&
            (mutableIndexSet = [[NSMutableIndexSet alloc] init]) != nil)
        {
            for (i = 0; i < n; ++i)
            {
                [mutableIndexSet
                    addIndex:[[[self document] tcpStreamController]
                                 indexForStream:[streams objectAtIndex:i]]];
            }
        }

        [streams release];
    }

    if (mutableIndexSet != nil)
    {
        [streamTableView selectRowIndexes:mutableIndexSet
                     byExtendingSelection:NO];
        [streamTableView scrollRowToVisible:[mutableIndexSet firstIndex]];
        [mutableIndexSet release];
    }

    [streamTableView
        setIndicatorImage:[[[self document] tcpStreamController] isReverseOrder]
                              ? [NSImage
                                    imageNamed:@"NSDescendingSortIndicator"]
                              : [NSImage imageNamed:@"NSAscendingSortIndicator"]
            inTableColumn:tableColumn];
    [streamTableView reloadData];
}

- (void)packetTableDidClickTableColumn:(NSTableColumn*)tableColumn
{
}

/* NSTableView delgate methods */

- (void)tableViewColumnDidMove:(NSNotification*)aNotification
{
    if (aNotification == nil || [aNotification object] == packetTableView)
        [self savePacketTableViewColumns];

    if (aNotification == nil || [aNotification object] == streamTableView)
        [self saveStreamTableViewColumns];
}

- (void)tableViewColumnDidResize:(NSNotification*)aNotification
{
    [self tableViewColumnDidMove:aNotification];
}

- (void)tableViewSelectionDidChange:(NSNotification*)aNotification
{
    NSInteger row;

    if (aNotification == nil || [aNotification object] == streamTableView)
    {
        row = [streamTableView selectedRow];
        [selectedStream release];
        selectedStream =
            [[[[self document] tcpStreamController] streamAtIndex:row] retain];
        [packetTableView reloadData];
    }
}

- (void)tableView:(NSTableView*)tableView
    didClickTableColumn:(NSTableColumn*)tableColumn
{
    if (tableView == packetTableView)
        [self packetTableDidClickTableColumn:tableColumn];
    else if (tableView == streamTableView)
        [self streamTableDidClickTableColumn:tableColumn];
}

- (void)tableView:(NSTableView*)tableView
    willDisplayCell:(id)cell
     forTableColumn:(NSTableColumn*)tableColumn
                row:(NSInteger)rowIndex
{
    if (tableView == packetTableView &&
        [cell isKindOfClass:[NSTextFieldCell class]])
    {
        if (![[selectedStream segmentAtIndex:rowIndex] isInOrder])
        {
            [cell setTextColor:[NSColor brownColor]];
        }
        else
            [cell setTextColor:[NSColor blackColor]];
    }
}

/* NSTableView data-source methods */

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView
{
    if (tableView == packetTableView)
    {
        return [self numberOfRowsInPacketTableView];
    }
    else if (tableView == streamTableView)
    {
        return [self numberOfRowsInStreamTableView];
    }

    return 0;
}

- (id)tableView:(NSTableView*)tableView
    objectValueForTableColumn:(NSTableColumn*)tableColumn
                          row:(NSInteger)rowIndex
{
    if (rowIndex < 0)
        return nil;

    if (tableView == packetTableView)
    {
        return [self packetTableObjectValueForTableColumn:tableColumn
                                                      row:rowIndex];
    }
    else if (tableView == streamTableView)
    {
        return [self streamTableObjectValueForTableColumn:tableColumn
                                                      row:rowIndex];
    }

    return nil;
}

- (void)sortStreamTable
{
    if ([[lastStreamTableColumn identifier]
            isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_SRC_IP_ADDRESS])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_SRC_IP_ADDRESS];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_DST_IP_ADDRESS])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_DST_IP_ADDRESS];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_SRC_HOSTNAME])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_SRC_HOSTNAME];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_DST_HOSTNAME])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_DST_HOSTNAME];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORT])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_SRC_PORT];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORT])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_DST_PORT];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORTNAME])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_SRC_PORTNAME];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORTNAME])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_DST_PORTNAME];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_SENT])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_BYTES_SENT];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_RECV])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_BYTES_RECV];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_TOTAL])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_BYTES_TOTAL];
    else if ([[lastStreamTableColumn identifier]
                 isEqualToString:PPSTREAMSWINDOW_STREAMS_TABLE_STATUS])
        [[[self document] tcpStreamController]
            sortStreams:PPSTREAM_SORT_STATUS];
}

- (void)updateWithUserScrolling
{
    [self update:autoScrolling];
}

- (void)update:(BOOL)shouldScroll
{
    /* if the stream was deleted by removing individual packets, release the stream
	   and select and display an appropriate stream */
    if (selectedStream != nil && [selectedStream packetsCount] == 0)
    {
        NSIndexSet* indexSet;
        NSInteger row;

        if ((row = [streamTableView selectedRow]) == -1 ||
            row >= [self numberOfRowsInStreamTableView])
        {
            --row;
            indexSet = [[NSIndexSet alloc] initWithIndex:row];
            [streamTableView selectRowIndexes:indexSet byExtendingSelection:NO];
            [streamTableView scrollRowToVisible:row];
            [indexSet release];
        }
        [selectedStream release];
        selectedStream =
            [[[[self document] tcpStreamController] streamAtIndex:row] retain];
    }

    [streamTableView noteNumberOfRowsChanged];
    [packetTableView noteNumberOfRowsChanged];

    if (lastStreamTableColumn != Nil)
        [self sortStreamTable];

    if (shouldScroll)
        [packetTableView scrollRowToVisible:[packetTableView numberOfRows] - 1];
}

- (BOOL)validateMenuItem:(NSMenuItem*)menuItem
{
    if ([menuItem action] == @selector(autoScrolling:) &&
        ![[self document] isLive])
        return NO;

    if ([menuItem tag] == PPSTREAMSWINDOW_PACKETS_TABLE_MENU_TAG &&
        ([menuItem action] == @selector(deleteButton:) ||
         [menuItem action] == @selector(reassembleStreamButton:)) &&
        [packetTableView selectedRow] == -1)
        return NO;

    if ([menuItem tag] == PPSTREAMSWINDOW_STREAMS_TABLE_MENU_TAG &&
        ([menuItem action] == @selector(deleteButton:) ||
         [menuItem action] == @selector(reassembleStreamButton:)) &&
        [streamTableView selectedRow] == -1)
        return NO;

    if ([menuItem action] == @selector(individualPacketButton:) &&
        [packetTableView selectedRow] == -1)
        return NO;

    if ([menuItem action] == @selector(deleteButton:) &&
        [[self window] firstResponder] != packetTableView &&
        [[self window] firstResponder] != streamTableView)
        return NO;

    return YES;
}

- (void)deleteSelectedPackets
{
    NSIndexSet* indexSet;
    NSRange range;
    size_t i, n, count;
    NSUInteger indexes[128];

    indexSet = [packetTableView selectedRowIndexes];

    range.location = [indexSet firstIndex];
    range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

    count = [indexSet count];

    if (count == [selectedStream packetsCount])
    {
        [[self document] deleteStream:selectedStream];

        [[self document] updateControllers];

        if ([streamTableView selectedRow] == -1)
        {
            if ((n = [streamTableView numberOfRows]) == 0)
                return;

            indexSet = [[NSIndexSet alloc] initWithIndex:n - 1];
            [streamTableView selectRowIndexes:indexSet byExtendingSelection:NO];
            [streamTableView scrollRowToVisible:n - 1];
            [indexSet release];
        }
        else
        {
            /* select a single stream only */
            [streamTableView
                    selectRowIndexes:[NSIndexSet
                                         indexSetWithIndex:[indexSet
                                                               firstIndex]]
                byExtendingSelection:NO];
            [streamTableView scrollRowToVisible:[indexSet firstIndex]];
            [self tableViewSelectionDidChange:nil];
        }

        return;
    }
    else
    {
        while ((n = [indexSet getIndexes:indexes
                                maxCount:(sizeof(indexes) / sizeof(indexes[0]))
                            inIndexRange:&range]) > 0)
        {
            for (i = 0; i < n; ++i)
            {
                [[selectedStream packetAtIndex:indexes[i]] setPendingDeletion];
            }
        }

        [[[self document] tcpStreamController]
            removePacketsAtIndexes:indexSet
                         forStream:selectedStream];
        [[self document] purgePacketsPendingDeletionWithHint:count];
    }

    [[self document] updateControllers];

    if ([packetTableView selectedRow] == -1)
    {
        if ((n = [packetTableView numberOfRows]) == 0)
            return;

        indexSet = [[NSIndexSet alloc] initWithIndex:n - 1];
        [packetTableView selectRowIndexes:indexSet byExtendingSelection:NO];
        [packetTableView scrollRowToVisible:n - 1];
        [indexSet release];
    }
    else
    {
        /* select a single packet only */
        [packetTableView
                selectRowIndexes:[NSIndexSet
                                     indexSetWithIndex:[indexSet firstIndex]]
            byExtendingSelection:NO];
        [packetTableView scrollRowToVisible:[indexSet firstIndex]];
    }
}

- (void)deleteSelectedStreams
{
    NSIndexSet* indexSet;
    NSRange range;
    NSUInteger indexes[128];
    NSUInteger i, n, adjust;

    indexSet = [streamTableView selectedRowIndexes];

    range.location = [indexSet firstIndex];
    range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

    adjust = 0;

    while ((n = [indexSet getIndexes:indexes
                            maxCount:(sizeof(indexes) / sizeof(indexes[0]))
                        inIndexRange:&range]) > 0)
    {
        for (i = 0; i < n; ++i)
        {
            [[self document] deleteStream:[[[self document] tcpStreamController]
                                              streamAtIndex:indexes[i] - adjust]
                              streamIndex:indexes[i] - adjust];
            ++adjust;
        }
    }

    [[self document] updateControllers];

    if ([streamTableView selectedRow] == -1)
    {
        if ((n = [streamTableView numberOfRows]) == 0)
            return;

        indexSet = [[NSIndexSet alloc] initWithIndex:n - 1];
        [streamTableView selectRowIndexes:indexSet byExtendingSelection:NO];
        [streamTableView scrollRowToVisible:n - 1];
        [indexSet release];
    }
    else
    {
        /* select a single stream only */
        [streamTableView
                selectRowIndexes:[NSIndexSet
                                     indexSetWithIndex:[indexSet firstIndex]]
            byExtendingSelection:NO];
        [streamTableView scrollRowToVisible:[indexSet firstIndex]];
        [self tableViewSelectionDidChange:nil];
    }
}

- (IBAction)deleteButton:(id)sender
{
    if (streamTableView == [[self window] firstResponder])
        [self deleteSelectedStreams];
    else if (packetTableView == [[self window] firstResponder])
        [self deleteSelectedPackets];
}

- (IBAction)individualPacketButton:(id)sender
{
    NSIndexSet* indexSet;
    NSRange range;
    NSUInteger indexes[128];
    NSUInteger i, n;

    indexSet = [packetTableView selectedRowIndexes];

    range.location = [indexSet firstIndex];
    range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

    while ((n = [indexSet getIndexes:indexes
                            maxCount:(sizeof(indexes) / sizeof(indexes[0]))
                        inIndexRange:&range]) > 0)
    {
        for (i = 0; i < n; ++i)
        {
            [[self document]
                displayIndividualWindow:[selectedStream
                                            packetAtIndex:indexes[i]]];
        }
    }
}

- (IBAction)reassembleStreamButton:(id)sender
{
    NSIndexSet* indexSet;
    NSRange range;
    NSUInteger indexes[128];
    NSUInteger i, n;

    if ([sender tag] == PPSTREAMSWINDOW_PACKETS_TABLE_MENU_TAG)
    {
        [[self document]
            displayReassemblyWindowForPacket:
                [selectedStream packetAtIndex:[packetTableView selectedRow]]];
        return;
    }

    indexSet = [streamTableView selectedRowIndexes];

    range.location = [indexSet firstIndex];
    range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

    while ((n = [indexSet getIndexes:indexes
                            maxCount:(sizeof(indexes) / sizeof(indexes[0]))
                        inIndexRange:&range]) > 0)
    {
        for (i = 0; i < n; ++i)
        {
            [[self document]
                displayReassemblyWindowForPacket:[[[[self document]
                                                     tcpStreamController]
                                                     streamAtIndex:indexes[i]]
                                                     packetAtIndex:0]];
        }
    }
}

- (IBAction)autoScrolling:(id)sender
{
    if ([sender state] == NSOffState)
    {
        autoScrolling = YES;
        [sender setState:NSOnState];
        [packetTableView scrollRowToVisible:[packetTableView numberOfRows] - 1];
    }
    else
    {
        autoScrolling = NO;
        [sender setState:NSOffState];
    }

    [[NSUserDefaults standardUserDefaults]
        setBool:autoScrolling
         forKey:PPSTREAMSWINDOW_AUTOSCROLLING];
}

- (BOOL)packetTableDoesAutoScroll
{
    return autoScrolling;
}

- (void)dealloc
{
    [selectedStream release];
    [lastPacketTableColumn release];
    [lastStreamTableColumn release];
    [super dealloc];
}

@end
