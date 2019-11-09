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

#ifndef _INVIDIVIDUALPACKETWINDOWCONTROLLER_H_
#define _INVIDIVIDUALPACKETWINDOWCONTROLLER_H_

#include "PacketPeeper.h"
#import <AppKit/NSOutlineView.h>
#import <AppKit/NSWindowController.h>

@class NSMutableArray;
@class NSOutlineView;
@class NSTableColumn;
@class NSMutableDictionary;
@class HFTextView;
@class Packet;
@class OutlineViewItem;
@class DataInspectorRepresenter;

@interface IndividualPacketWindowController
    : NSWindowController <NSOutlineViewDataSource>
{
    IBOutlet NSOutlineView* packetOutlineView;
    IBOutlet HFTextView* packetHexView;
    OutlineViewItem* packetItems;
    Packet* packet;
    NSMutableDictionary* expandedItems;
    DataInspectorRepresenter* dataInspectorRepresenter;
}

- (id)initWithPacket:(Packet*)aPacket;
- (void)setPacket:(Packet*)aPacket;
- (Packet*)packet;
- (void)hostNameLookupCompletedNotification:(NSNotification*)note;

/* NSOutlineView data-source methods */

- (BOOL)outlineView:(NSOutlineView*)outlineView isItemExpandable:(id)item;
- (NSInteger)outlineView:(NSOutlineView*)outlineView
    numberOfChildrenOfItem:(id)item;
- (id)outlineView:(NSOutlineView*)outlineView
            child:(int)anIndex
           ofItem:(id)item;
- (id)outlineView:(NSOutlineView*)outlineView
    objectValueForTableColumn:(NSTableColumn*)tableColumn
                       byItem:(id)item;

- (IBAction)toggleDataInspectorView:(id)sender;
- (bool)isDataInspectorViewVisible;
@end

#endif
