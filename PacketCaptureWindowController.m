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

#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#import <Foundation/NSIndexSet.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSRunLoop.h>
#import <Foundation/NSUserDefaults.h>
#import <Foundation/NSDate.h>
#import <Foundation/NSData.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSArchiver.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSToolbarItem.h>
#import <AppKit/NSWindow.h>
#import <AppKit/NSImage.h>
#import <AppKit/NSMenu.h>
#import <AppKit/NSEvent.h>
#import <AppKit/NSTableColumn.h>
#import <AppKit/NSCell.h>
#import <AppKit/NSTextField.h>
#import <AppKit/NSTableHeaderView.h>
#include "AppController.h"
#include "Packet.h"
#include "PPPacketUIAdditons.h"
#include "pkt_compare.h"
#include "PPTCPStream.h"
#include "TCPDecode.h"
#include "IPV4Decode.h"
#include "PPTableView.h"
#include "MyDocument.h"
#include "AppController.h"
#include "PPDataQuantityFormatter.h"
#include "ColumnIdentifier.h"
#include "DateFormat.h"
#include "syncmenu.h"
#include "PacketCaptureWindowController.h"
#include "PacketPeeper.h"


#define	PACKETCAPTURE_TOOLBAR_ID	@"PacketCaptureToolbar"		/* identifier for the NSToolbar itself */

/* default toolbar buttons */
#define NEXT_TOOLBARITEM_ID			@"NextItem"					/* ``next packet in list'' button */
#define PREV_TOOLBARITEM_ID			@"PrevItem"					/* ``previous packet in list'' button */
#define FIRST_TOOLBARITEM_ID		@"FirstItem"				/* ``first packet in list'' button */
#define LAST_TOOLBARITEM_ID			@"LastItem"					/* ``last packet in list'' button */
#define DELETE_TOOLBARITEM_ID		@"DeleteItem"				/* ``delete packet'' button */
#define STOP_TOOLBARITEM_ID			@"StopItem"					/* ``stop capture'' button */
#define FILTER_TOOLBARITEM_ID		@"FilterItem"				/* ``filters'' button */
#define CLEAR_FILTER_TOOLBARITEM_ID	@"ClearFilterItem"			/* ``clear filters'' button */

@implementation PacketCaptureWindowController

- (void)selectPacketAtIndex:(NSUInteger)index
{
    if ([packetTableView numberOfRows] > index)
        [packetTableView selectRowIndexes:[NSIndexSet indexSetWithIndex:index] byExtendingSelection:NO];
}

- (void)windowDidLoad
{
	autoScrolling = [[NSUserDefaults standardUserDefaults] boolForKey:PPDOCUMENT_AUTOSCROLLING];
	lastColumn = nil;

	/* super sets up HexView and NSOutlineView */
	[super windowDidLoad];
	[self setupToolbar];

	[packetTableView setDataSource:self];
	[packetTableView setDelegate:self];
	[packetTableView setTarget:self];
	[packetTableView setDoubleAction:@selector(doubleAction:)];

	/* itunes also has `Auto Size Column' `Auto Size All Columns', could be something to add */
	[[packetTableView headerView] setMenu:[(AppController*)[NSApp delegate] createProtocolsMenu]];

	[self populatePacketTableView];

	syncMenu([self packetTableColumnMenu], [self columnIdentifierStrings]);

	[packetTableView setColumnAutoresizingStyle:NSTableViewNoColumnAutoresizing];

	if([[self document] interface] != nil)
		[self update:NO];
}

- (void)hostNameLookupCompletedNotification:(NSNotification *)note
{
	[packetTableView reloadData];
	[super hostNameLookupCompletedNotification:note];
}

- (NSMenu *)packetTableColumnMenu
{
	return [[packetTableView headerView] menu];
}

- (NSString *)windowTitleForDocumentDisplayName:(NSString *)displayName
{
	if([[self document] interface] != nil)
		return [NSString stringWithFormat:@"%@ - %@", displayName, [[self document] interface]];

	return [NSString stringWithFormat:@"%@ - Capture Setup", displayName];
}

- (BOOL)shouldCloseDocument
{
	/* the document is closed when this window closes */
	return YES;
}

- (void)doubleAction:(id)sender
{
	int row;

	if((row = [sender clickedRow]) != -1)
		[[self document] displayIndividualWindow:[[self document] packetAtIndex:row]];
}

- (void)sortPackets
{
    // XXX WONTFIX
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
	[[self document] sortPacketsWithColumn:[lastColumn identifier]];
#pragma clang diagnostic pop
}

- (void)populatePacketTableView
{
	NSData *arrayAsData;
	NSArray *columns;
	unsigned int i;

	if((arrayAsData = [[NSUserDefaults standardUserDefaults] objectForKey:PPDOCUMENT_TABLEVIEW_COLUMNS_KEY]) == nil)
		return;

	if((columns = [NSUnarchiver unarchiveObjectWithData:arrayAsData]) == nil)
		return;

	for(i = 0; i < [columns count]; ++i)
		[packetTableView addTableColumn:[columns objectAtIndex:i]];
}

- (void)savePacketTableViewColumns
{
	NSData *data;

	data = [NSArchiver archivedDataWithRootObject:[packetTableView tableColumns]];

	[[NSUserDefaults standardUserDefaults] setObject:data forKey:PPDOCUMENT_TABLEVIEW_COLUMNS_KEY];
}

- (NSMutableArray *)columnIdentifierStrings
{
	NSArray *columns;
	NSMutableArray *ret;
	unsigned int i;

	columns = [packetTableView tableColumns];
	ret = [[NSMutableArray alloc] initWithCapacity:[columns count]];

	for(i = 0; i < [columns count]; ++i)
		[ret addObject:[[columns objectAtIndex:i] identifier]];

	return [ret autorelease];
}

/* NSTableView data source methods */

- (int)numberOfRowsInTableView:(NSTableView *)tableView
{
	return [[self document] numberOfPackets];
}

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(int)rowIndex
{
	if(rowIndex < 0)
		return nil;

    // XXX WONTFIX
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
	return [[[self document] packetAtIndex:rowIndex] stringForColumn:[tableColumn identifier]];
#pragma clang diagnostic pop
}

/* NSTableView delegate methods */

- (void)tableViewColumnDidMove:(NSNotification *)aNotification
{
	[self savePacketTableViewColumns];
}

- (void)tableViewColumnDidResize:(NSNotification *)aNotification
{
	[self savePacketTableViewColumns];
}

- (void)tableViewSelectionDidChange:(NSNotification *)aNotification
{
	[self setPacket:[[self document] packetAtIndex:[packetTableView selectedRow]]];
}

- (void)tableView:(NSTableView *)tableView didClickTableColumn:(NSTableColumn *)tableColumn
{
	NSMutableIndexSet *mutableIndexSet;
	NSIndexSet *indexSet;
	NSRange range;
	NSUInteger indexes[128];
	unsigned int i, n;

	mutableIndexSet = nil;

	if(lastColumn == tableColumn) {
		unsigned int n_pkts;

		/* same column clicked, so reverse the sort order */
		if((mutableIndexSet = [[NSMutableIndexSet alloc] init]) == nil)
			return;

		indexSet = [packetTableView selectedRowIndexes];
		n_pkts = [[self document] numberOfPackets];

		range.location = [indexSet firstIndex];
		range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

		/* reverse each index in the set */
		while((n = [indexSet getIndexes:indexes maxCount:(sizeof(indexes) / sizeof(indexes[0])) inIndexRange:&range]) > 0) {
			for(i = 0; i < n; ++i) {
				[mutableIndexSet addIndex:(n_pkts - indexes[i]) - 1];
			}
		}

		[[self document] setReversePacketOrder:![[self document] isReverseOrder]];
	} else {
		NSMutableArray *packets;

		/* different column clicked, sort normally */
		[[self document] setReversePacketOrder:NO];

		if(lastColumn != nil) {
			[packetTableView setIndicatorImage:nil inTableColumn:lastColumn];
			[lastColumn release];
		}

		lastColumn = [tableColumn retain];
		[packetTableView setHighlightedTableColumn:tableColumn];

		if((packets = [[NSMutableArray alloc] init]) != nil) {
			indexSet = [packetTableView selectedRowIndexes];
			range.location = [indexSet firstIndex];
			range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

			while((n = [indexSet getIndexes:indexes maxCount:(sizeof(indexes) / sizeof(indexes[0])) inIndexRange:&range]) > 0) {
				for(i = 0; i < n; ++i)
					[packets addObject:[[self document] packetAtIndex:indexes[i]]];
			}
		}

		[self sortPackets];

		n = [packets count];

		if(n > 0 && packets != nil && (mutableIndexSet = [[NSMutableIndexSet alloc] init]) != nil) {
			for(i = 0; i < n; ++i) {
				[mutableIndexSet addIndex:[[self document] indexForPacket:[packets objectAtIndex:i]]];
			}
		}

		[packets release];
	}

	if(mutableIndexSet != nil) {
		[packetTableView selectRowIndexes:mutableIndexSet byExtendingSelection:NO];
		[packetTableView scrollRowToVisible:[mutableIndexSet firstIndex]];
		[mutableIndexSet release];
	}

	[packetTableView setIndicatorImage:[[self document] isReverseOrder] ?
	[NSImage imageNamed:@"NSDescendingSortIndicator"] :
	[NSImage imageNamed:@"NSAscendingSortIndicator"] inTableColumn:tableColumn];
	[packetTableView reloadData];
}

/* NSToolbar delegate methods */

- (NSToolbarItem *)toolbar:(NSToolbar *)toolbar itemForItemIdentifier:(NSString *)itemIdentifier
						   willBeInsertedIntoToolbar:(BOOL)flag
{
	NSToolbarItem *toolbarItem;

	toolbarItem = [[NSToolbarItem alloc] initWithItemIdentifier:itemIdentifier];

	if([itemIdentifier isEqualToString:NEXT_TOOLBARITEM_ID]) {
		[toolbarItem setLabel:@"Next"];
		[toolbarItem setPaletteLabel:@"Next Packet Button"];
		[toolbarItem setToolTip:@"Move to the next packet received"];
		[toolbarItem setImage:[NSImage imageNamed:@"next"]];
		[toolbarItem setTarget:self];
		[toolbarItem setAction:@selector(nextButton:)];
	} else if([itemIdentifier isEqualToString:PREV_TOOLBARITEM_ID]) {
		[toolbarItem setLabel:@"Prev"];
		[toolbarItem setPaletteLabel:@"Previous Packet Button"];
		[toolbarItem setToolTip:@"Move to the previous packet received"];
		[toolbarItem setImage:[NSImage imageNamed:@"prev"]];
		[toolbarItem setTarget:self];
		[toolbarItem setAction:@selector(prevButton:)];
	} else if([itemIdentifier isEqualToString:FIRST_TOOLBARITEM_ID]) {
		[toolbarItem setLabel:@"First"];
		[toolbarItem setPaletteLabel:@"First Packet Button"];
		[toolbarItem setToolTip:@"Move to the first packet received"];
		[toolbarItem setImage:[NSImage imageNamed:@"first"]];
		[toolbarItem setTarget:self];
		[toolbarItem setAction:@selector(firstButton:)];
	} else if([itemIdentifier isEqualToString:LAST_TOOLBARITEM_ID]) {
		[toolbarItem setLabel:@"Last"];
		[toolbarItem setPaletteLabel:@"Last Packet Button"];
		[toolbarItem setToolTip:@"Move to the last packet received"];
		[toolbarItem setImage:[NSImage imageNamed:@"last"]];
		[toolbarItem setTarget:self];
		[toolbarItem setAction:@selector(lastButton:)];
	} else if([itemIdentifier isEqualToString:DELETE_TOOLBARITEM_ID]) {
		[toolbarItem setLabel:@"Delete"];
		[toolbarItem setPaletteLabel:@"Delete Packet Button"];
		[toolbarItem setToolTip:@"Delete the currently selected packet"];
		[toolbarItem setImage:[NSImage imageNamed:@"delete"]];
		[toolbarItem setTarget:self];
		[toolbarItem setAction:@selector(deleteButton:)];
	} else if([itemIdentifier isEqualToString:STOP_TOOLBARITEM_ID]) {
		[toolbarItem setLabel:@"Stop"];
		[toolbarItem setPaletteLabel:@"Stop Capture Button"];
		[toolbarItem setToolTip:@"Stop this capture session"];
		[toolbarItem setImage:[NSImage imageNamed:@"stop"]];
		[toolbarItem setTarget:self];
		[toolbarItem setAction:@selector(stopButton:)];
	} else if([itemIdentifier isEqualToString:FILTER_TOOLBARITEM_ID]) {
		[toolbarItem setLabel:@"Filters"];
		[toolbarItem setPaletteLabel:@"Setup Capture Filters Button"];
		[toolbarItem setToolTip:@"Setup capture filters"];
		[toolbarItem setImage:[NSImage imageNamed:@"filters"]];
		[toolbarItem setTarget:self];
		[toolbarItem setAction:@selector(filterButton:)];
	} else if([itemIdentifier isEqualToString:CLEAR_FILTER_TOOLBARITEM_ID]) {
		[toolbarItem setLabel:@"Clear Filter"];
		[toolbarItem setPaletteLabel:@"Clear Capture Filter Button"];
		[toolbarItem setToolTip:@"Clear the current capture filter"];
		[toolbarItem setImage:[NSImage imageNamed:@"clear_filters"]];
		[toolbarItem setTarget:self];
		[toolbarItem setAction:@selector(clearFilterButton:)];
	} else
		return nil;

	return [toolbarItem autorelease];
}

- (NSArray *)toolbarAllowedItemIdentifiers:(NSToolbar *)toolbar
{
	return [NSArray arrayWithObjects:NSToolbarSeparatorItemIdentifier,
			NSToolbarSpaceItemIdentifier, NSToolbarFlexibleSpaceItemIdentifier,
			NSToolbarCustomizeToolbarItemIdentifier, NEXT_TOOLBARITEM_ID,
			PREV_TOOLBARITEM_ID, FIRST_TOOLBARITEM_ID, LAST_TOOLBARITEM_ID,
			DELETE_TOOLBARITEM_ID, STOP_TOOLBARITEM_ID, FILTER_TOOLBARITEM_ID,
			CLEAR_FILTER_TOOLBARITEM_ID, nil];
}

- (NSArray *)toolbarDefaultItemIdentifiers:(NSToolbar *)toolbar
{
	return [NSArray arrayWithObjects:FIRST_TOOLBARITEM_ID, PREV_TOOLBARITEM_ID,
			NEXT_TOOLBARITEM_ID, LAST_TOOLBARITEM_ID, NSToolbarSeparatorItemIdentifier,
			DELETE_TOOLBARITEM_ID, NSToolbarSeparatorItemIdentifier, STOP_TOOLBARITEM_ID,
			NSToolbarSeparatorItemIdentifier, FILTER_TOOLBARITEM_ID, CLEAR_FILTER_TOOLBARITEM_ID,
			NSToolbarSeparatorItemIdentifier, nil];
}

- (void)setupToolbar
{
	NSToolbar *toolbar;

	toolbar = [[NSToolbar alloc] initWithIdentifier:PACKETCAPTURE_TOOLBAR_ID];
	[toolbar setAllowsUserCustomization:YES];
	[toolbar setAutosavesConfiguration:YES];
	[toolbar setDisplayMode:NSToolbarDisplayModeIconOnly];
	[toolbar setDelegate:self];
	[[self window] setToolbar:toolbar];
	[toolbar release];
}

- (BOOL)validateToolbarItem:(NSToolbarItem *)theItem
{
	if([[theItem itemIdentifier] isEqualToString:LAST_TOOLBARITEM_ID]) {
		unsigned int total;
		total = [packetTableView numberOfRows];
		return ([packetTableView selectedRow] != (total - 1) && total != 0);
	}

	if([[theItem itemIdentifier] isEqualToString:NEXT_TOOLBARITEM_ID]) {
		unsigned int row;
		return ((row = [packetTableView selectedRow]) != -1 && row != ([packetTableView numberOfRows] - 1));
	}

	if([[theItem itemIdentifier] isEqualToString:FIRST_TOOLBARITEM_ID])
		return ([packetTableView selectedRow] != 0 && [packetTableView numberOfRows] != 0);

	if([[theItem itemIdentifier] isEqualToString:PREV_TOOLBARITEM_ID]) {
		unsigned int row;
		return ((row = [packetTableView selectedRow]) != -1 && row != 0);
	}

	if([[theItem itemIdentifier] isEqualToString:STOP_TOOLBARITEM_ID])
		return [[self document] isLive];

	if([[theItem itemIdentifier] isEqualToString:DELETE_TOOLBARITEM_ID])
		return ([packetTableView selectedRow] != -1);

	if([[theItem itemIdentifier] isEqualToString:CLEAR_FILTER_TOOLBARITEM_ID])
		return ([[self document] filterProgram] != nil);

	return YES;
}

- (BOOL)validateMenuItem:(NSMenuItem *)menuItem
{
	if([menuItem action] == @selector(autoScrolling:) && ![[self document] isLive])
		return NO;

	if([menuItem action] == @selector(stopButton:) && ![[self document] isLive])
		return NO;

	if([menuItem action] == @selector(deleteButton:) && [packetTableView selectedRow] == -1)
		return NO;

	if([menuItem action] == @selector(individualPacketButton:) &&
	   [packetTableView selectedRow] == -1)
		return NO;

	if([menuItem action] == @selector(reassembleStreamButton:)) {
		TCPDecode *segment;
		PPTCPStream *stream;

		if((segment = [[[self document] packetAtIndex:[packetTableView selectedRow]] decoderForClass:[TCPDecode class]]) == nil)
			return NO;
		if((stream = [segment backPointer]) == NULL)
			return NO;
		return [stream isValid];
	}

	if([menuItem action] == @selector(clearFilterButton:) ||
	   [menuItem action] == @selector(discardPacketsAndClearFilterButton:))
		return ([[self document] filterProgram] != nil);

	return YES;
}

- (void)updateWithUserScrolling
{
	[self update:autoScrolling];
}

- (void)update:(BOOL)shouldScroll
{
	if([lastColumn identifier] != [Packet class] &&
		[(ColumnIdentifier *)[lastColumn identifier] index] != PACKET_COLUMN_INDEX_NUMBER &&
		[(ColumnIdentifier *)[lastColumn identifier] index] != PACKET_COLUMN_INDEX_DATE) {
		[self sortPackets];
	}

	[packetTableView noteNumberOfRowsChanged];
	[statusTextField setStringValue:[NSString stringWithFormat:@"%u packets, %@",
											  [[self document] numberOfPackets],
											  data_quantity_str([[self document] numberOfBytes])]];

	if(shouldScroll)
		[packetTableView scrollRowToVisible:[packetTableView numberOfRows] - 1];

	[[[self window] toolbar] validateVisibleItems];
}

- (BOOL)packetTableDoesAutoScroll
{
	return autoScrolling;
}

- (void)cancelEndingButtonSetHidden:(BOOL)flag
{
	[cancelEndingButton setHidden:flag];
}

- (IBAction)autoScrolling:(id)sender
{
	if([sender state] == NSOffState) {
		autoScrolling = YES;
		[sender setState:NSOnState];
		[packetTableView scrollRowToVisible:[packetTableView numberOfRows] - 1];
	} else {
		autoScrolling = NO;
		[sender setState:NSOffState];
	}

	[[NSUserDefaults standardUserDefaults] setBool:autoScrolling forKey:PPDOCUMENT_AUTOSCROLLING];
}

- (IBAction)columnMenuAction:(id)sender
{
	NSTableColumn *column;
	id identifier;

	if([sender state] == NSOffState) {
		identifier = [sender representedObject];
		column = [[NSTableColumn alloc] initWithIdentifier:identifier];

		[[column headerCell] setStringValue:[identifier shortName]];

		[column setEditable:NO];
		[packetTableView addTableColumn:column];
		[column release];
		[sender setState:NSOnState];
	} else if([packetTableView numberOfColumns] > 1) { /* the user must have at least one column */
		[packetTableView removeTableColumn:[packetTableView tableColumnWithIdentifier:[sender representedObject]]];
		[sender setState:NSOffState];
	}

	[self savePacketTableViewColumns];
}

- (IBAction)firstButton:(id)sender
{
	NSIndexSet *indexSet;

	if([packetTableView numberOfRows] == 0)
		return;

	indexSet = [[NSIndexSet alloc] initWithIndex:0];
	[packetTableView selectRowIndexes:indexSet byExtendingSelection:NO];
	[packetTableView scrollRowToVisible:0];
	[indexSet release];
}

- (IBAction)lastButton:(id)sender
{
	NSIndexSet *indexSet;
	unsigned int total;

	if((total = [packetTableView numberOfRows]) == 0)
		return;

	indexSet = [[NSIndexSet alloc] initWithIndex:total - 1];
	[packetTableView selectRowIndexes:indexSet byExtendingSelection:NO];
	[packetTableView scrollRowToVisible:total - 1];
	[indexSet release];
}

- (IBAction)nextButton:(id)sender
{
	NSIndexSet *indexSet;
	int packetIndex;
	int total;

	packetIndex = [packetTableView selectedRow];
	total = [packetTableView numberOfRows];

	/* if nothing is in the table or we cannot go further, do nothing */
	if(packetIndex == (total - 1) || total == 0)
		return;

	/* -1 indicates no selection */
	if(packetIndex == -1)
		packetIndex = 0;
	else
		++packetIndex;

	indexSet = [[NSIndexSet alloc] initWithIndex:packetIndex];

	[packetTableView selectRowIndexes:indexSet byExtendingSelection:NO];
	[packetTableView scrollRowToVisible:packetIndex];
	[indexSet release];
}

- (IBAction)prevButton:(id)sender
{
	NSIndexSet *indexSet;
	int packetIndex;

	packetIndex = [packetTableView selectedRow];

	if(packetIndex == 0 || [packetTableView numberOfRows] == 0)
		return;

	if(packetIndex == -1)
		packetIndex = 0;
	else
		--packetIndex;

	indexSet = [[NSIndexSet alloc] initWithIndex:packetIndex];

	[packetTableView selectRowIndexes:indexSet byExtendingSelection:NO];
	[packetTableView scrollRowToVisible:packetIndex];
	[indexSet release];
}

- (IBAction)stopButton:(id)sender
{
	[[self document] stopCapture];
}

- (IBAction)filterButton:(id)sender
{
	[[self document] displayFilterSheet];
}

- (IBAction)clearFilterButton:(id)sender
{
	[[self document] clearFilterProgram:NO];
}

- (IBAction)discardPacketsAndClearFilterButton:(id)sender
{
	[[self document] clearFilterProgram:YES];
}

- (IBAction)deleteButton:(id)sender
{
	NSIndexSet *indexSet;
	NSRange range;
	NSUInteger indexes[128];
	unsigned int i, n, adjust;

	indexSet = [packetTableView selectedRowIndexes];

	range.location = [indexSet firstIndex];
	range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

	adjust = 0;

	while((n = [indexSet getIndexes:indexes maxCount:(sizeof(indexes) / sizeof(indexes[0])) inIndexRange:&range]) > 0) {
		for(i = 0; i < n; ++i)
			[[self document] deletePacketAtIndex:indexes[i] - adjust++];
	}

	/* TODO: When items are deleted from the packet list, if any deleted items are selected in the streams view,
	   deselect them, and vice versa. */
	[[self document] updateControllers];

	if([packetTableView selectedRow] == -1)
		[self lastButton:nil];
	else {
		/* select a single packet only */
		[packetTableView selectRowIndexes:[NSIndexSet indexSetWithIndex:[indexSet firstIndex]] byExtendingSelection:NO];
		[packetTableView scrollRowToVisible:[indexSet firstIndex]];
		[self tableViewSelectionDidChange:nil];
	}
}

- (IBAction)individualPacketButton:(id)sender
{
	NSIndexSet *indexSet;
	NSRange range;
	NSUInteger indexes[128];
	unsigned int i, n;

	indexSet = [packetTableView selectedRowIndexes];

	range.location = [indexSet firstIndex];
	range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

	while((n = [indexSet getIndexes:indexes maxCount:(sizeof(indexes) / sizeof(indexes[0])) inIndexRange:&range]) > 0) {
		for(i = 0; i < n; ++i) {
			[[self document] displayIndividualWindow:[[self document] packetAtIndex:indexes[i]]];
		}
	}
}

- (IBAction)flushHostnamesButton:(id)sender
{
	[[self document] flushHostnames];
}

- (IBAction)reassembleStreamButton:(id)sender
{
	NSIndexSet *indexSet;
	NSRange range;
	NSUInteger indexes[128];
	unsigned int i, n;

	indexSet = [packetTableView selectedRowIndexes];

	range.location = [indexSet firstIndex];
	range.length = ([indexSet lastIndex] - [indexSet firstIndex]) + 1;

	while((n = [indexSet getIndexes:indexes maxCount:(sizeof(indexes) / sizeof(indexes[0])) inIndexRange:&range]) > 0) {
		for(i = 0; i < n; ++i)
			[[self document] displayReassemblyWindowForPacket:[[self document] packetAtIndex:indexes[i]]];
	}
}

- (IBAction)streamsWindowButton:(id)sender
{
	[[self document] displayStreamsWindow];
}

- (IBAction)nodeGraphButton:(id)sender
{
	[[self document] displayNodeGraphWindow];
}

- (IBAction)cancelEndingButton:(id)sender
{
	[[self document] cancelEndingConditions];
	[cancelEndingButton setHidden:YES];
}

- (void)dealloc
{
	[lastColumn release];
	[super dealloc];
}

@end
