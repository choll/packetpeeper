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

#ifndef _PACKETCAPTUREWINDOWCONTROLLER_H_
#define _PACKETCAPTUREWINDOWCONTROLLER_H_

#import <AppKit/NSTableView.h>
#import <AppKit/NSToolbar.h>
#include "IndividualPacketWindowController.h"

@class NSToolbar;
@class NSToolbarItem;
@class NSString;
@class NSArray;
@class NSMenuItem;
@class NSNotification;
@class NSTableView;
@class PPTableView;
@class PPOutlineView;
@class NSButton;
@class NSTextField;

@interface PacketCaptureWindowController : IndividualPacketWindowController <NSTableViewDataSource, NSTableViewDelegate, NSToolbarDelegate>
{
	IBOutlet PPTableView *packetTableView;
	IBOutlet NSTextField *statusTextField;
	IBOutlet NSButton *cancelEndingButton;
	NSTableColumn *lastColumn;
	BOOL autoScrolling;
}

- (void)selectPacketAtIndex:(NSUInteger)index;

- (NSMenu *)packetTableColumnMenu;
- (void)doubleAction:(id)sender;
- (void)populatePacketTableView; /* private method */
- (void)savePacketTableViewColumns; /* private method */

- (NSMutableArray *)columnIdentifierStrings;

/* NSTableView delegate methods */
- (void)tableViewColumnDidMove:(NSNotification *)aNotification;
- (void)tableViewColumnDidResize:(NSNotification *)aNotification;
- (void)tableViewSelectionDidChange:(NSNotification *)aNotification;

- (void)tableView:(NSTableView *)tableView didClickTableColumn:(NSTableColumn *)tableColumn;

/* NSTableView data-source methods */

- (int)numberOfRowsInTableView:(NSTableView *)tableView;

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn
				row:(int)rowIndex;

/* NSToolbar delegate methods */
- (NSToolbarItem *)toolbar:(NSToolbar *)toolbar itemForItemIdentifier:(NSString *)itemIdentifier
						   willBeInsertedIntoToolbar:(BOOL)flag;
- (NSArray *)toolbarAllowedItemIdentifiers:(NSToolbar *)toolbar;
- (NSArray *)toolbarDefaultItemIdentifiers:(NSToolbar *)toolbar;

- (void)setupToolbar;
- (BOOL)validateToolbarItem:(NSToolbarItem *)theItem;
- (BOOL)validateMenuItem:(NSMenuItem *)menuItem;

- (void)updateWithUserScrolling;
- (void)update:(BOOL)shouldScroll;
- (BOOL)packetTableDoesAutoScroll;
- (void)cancelEndingButtonSetHidden:(BOOL)flag;
- (IBAction)autoScrolling:(id)sender;
- (IBAction)columnMenuAction:(id)sender;
- (IBAction)firstButton:(id)sender;
- (IBAction)lastButton:(id)sender;
- (IBAction)nextButton:(id)sender;
- (IBAction)prevButton:(id)sender;
- (IBAction)stopButton:(id)sender;
- (IBAction)filterButton:(id)sender;
- (IBAction)clearFilterButton:(id)sender;
- (IBAction)discardPacketsAndClearFilterButton:(id)sender;
- (IBAction)deleteButton:(id)sender;
- (IBAction)individualPacketButton:(id)sender;
- (IBAction)flushHostnamesButton:(id)sender;
- (IBAction)reassembleStreamButton:(id)sender;
//- (IBAction)showStreamPacket:(id)sender;
- (IBAction)nodeGraphButton:(id)sender;
- (IBAction)streamsWindowButton:(id)sender;
- (IBAction)cancelEndingButton:(id)sender;

@end

#endif
