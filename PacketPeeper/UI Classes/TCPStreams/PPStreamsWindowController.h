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

#ifndef _PPSTREAMSWINDOWCONTROLLER_H_
#define _PPSTREAMSWINDOWCONTROLLER_H_

#import <AppKit/NSTableView.h>
#import <AppKit/NSWindowController.h>

@class NSTableView;
@class NSSearchField;
@class NSTableColumn;
@class NSMenu;
@class NSMutableArray;
@class PPTCPStream;

@interface PPStreamsWindowController
    : NSWindowController <NSTableViewDataSource, NSTableViewDelegate>
{
    IBOutlet NSTableView* streamTableView;
    IBOutlet NSTableView* packetTableView;
    PPTCPStream* selectedStream;
    NSTableColumn* lastPacketTableColumn;
    NSTableColumn* lastStreamTableColumn;
    BOOL autoScrolling;
}

+ (NSMenu*)createStreamTableMenu;
- (void)hostNameLookupCompletedNotification:(NSNotification*)note;
- (void)populatePacketTableView;
- (void)populateStreamTableView;
- (void)doubleAction:(id)sender;
- (IBAction)columnMenuAction:(id)sender;
- (void)savePacketTableViewColumns;
- (void)saveStreamTableViewColumns;
- (NSMutableArray*)tableColumnIdentifierStringsForTableColumns:
    (NSArray*)tableColumns;
- (NSMutableArray*)packetTableColumnIdentifierStrings;
- (NSMutableArray*)streamTableColumnIdentifierStrings;
- (NSMenu*)packetTableColumnMenu;
- (NSMenu*)streamTableColumnMenu;
- (void)tableViewSelectionDidChange:(NSNotification*)aNotification;
- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView;
- (NSInteger)numberOfRowsInPacketTableView;
- (NSInteger)numberOfRowsInStreamTableView;
- (id)packetTableObjectValueForTableColumn:(NSTableColumn*)tableColumn
                                       row:(NSInteger)rowIndex;
- (id)streamTableObjectValueForTableColumn:(NSTableColumn*)tableColumn
                                       row:(NSInteger)rowIndex;
- (id)tableView:(NSTableView*)tableView
    objectValueForTableColumn:(NSTableColumn*)tableColumn
                          row:(NSInteger)rowIndex;
- (void)sortStreamTable;
- (void)updateWithUserScrolling;
- (void)update:(BOOL)shouldScroll;

- (BOOL)validateMenuItem:(NSMenuItem*)menuItem;
- (IBAction)deleteButton:(id)sender;
- (void)deleteSelectedPackets;
- (void)deleteSelectedStreams;
- (IBAction)individualPacketButton:(id)sender;
- (IBAction)reassembleStreamButton:(id)sender;

@end

#endif
