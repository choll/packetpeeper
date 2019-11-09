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

#ifndef PACKETPEEPER_ARP_SPOOFING_WINDOW_CONTROLLER_H
#define PACKETPEEPER_ARP_SPOOFING_WINDOW_CONTROLLER_H

#import <AppKit/NSComboBoxCell.h>
#import <AppKit/NSTableView.h>
#import <AppKit/NSWindowController.h>

@class NSButton;
@class NSTableView;
@class NSTableColumn;
@class NSTextField;
@class NSProgressIndicator;
@class NSMutableArray;

@interface PPArpSpoofingWindowController : NSWindowController <
                                               NSTableViewDataSource,
                                               NSTableViewDelegate,
                                               NSComboBoxCellDataSource>
{
    IBOutlet NSTableView* targetsTableView_;
    IBOutlet NSTextField* statusTextField_;
    IBOutlet NSProgressIndicator* progressIndicator_;
    NSMutableArray* targetsArray_;
    NSMutableArray* neighbouringHostsArray_;
}

- (IBAction)startSpoofingButton:(id)sender;
- (IBAction)stopSpoofingButton:(id)sender;
- (IBAction)scanLocalSubnetButton:(id)sender;
- (IBAction)addTargetsTableRow:(id)sender;
- (IBAction)removeTargetsTableRow:(id)sender;
- (IBAction)helpButton:(id)sender;

// NSTableView data-source methods
- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView;
- (id)tableView:(NSTableView*)tableView
    objectValueForTableColumn:(NSTableColumn*)tableColumn
                          row:(NSInteger)rowIndex;

// NSComboBoxCell data-source methods
- (id)comboBoxCell:(NSComboBoxCell*)aComboBoxCell
    objectValueForItemAtIndex:(NSInteger)index;
- (NSInteger)numberOfItemsInComboBoxCell:(NSComboBoxCell*)aComboBoxCell;

@end

#endif
