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

#import <AppKit/NSOutlineView.h>
#import <AppKit/NSWindowController.h>
#include "HexView.h"
#include "PacketPeeper.h"

@class NSMutableArray;
@class NSOutlineView;
@class NSTableColumn;
@class NSMutableDictionary;
@class Packet;
@class OutlineViewItem;

@interface IndividualPacketWindowController : NSWindowController <HexViewDataSource, NSOutlineViewDataSource> {
	IBOutlet NSOutlineView *packetOutlineView;
	IBOutlet HexView *packetHexView;
	OutlineViewItem *packetItems;
	Packet *packet;
	NSMutableDictionary *expandedItems;
}

- (id)initWithPacket:(Packet *)aPacket;

- (void)setPacket:(Packet *)aPacket;

- (Packet *)packet;

- (void)hostNameLookupCompletedNotification:(NSNotification *)note;

/* NSOutlineView data-source methods */

- (BOOL)outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item;

- (int)outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item;

- (id)outlineView:(NSOutlineView *)outlineView child:(int)index ofItem:(id)item;

- (id)outlineView:(NSOutlineView *)outlineView objectValueForTableColumn:(NSTableColumn *)tableColumn byItem:(id)item;

/* HexView data-source methods */

- (unsigned int)length;

- (const void *)bytes;

@end

#endif
