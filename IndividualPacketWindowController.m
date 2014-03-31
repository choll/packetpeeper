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

#import <Foundation/NSTimer.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#import <Foundation/NSDate.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSValue.h>
#import <Foundation/NSDecimalNumber.h>
#import <Foundation/NSDictionary.h>
#import <AppKit/NSOutlineView.h>
#import <AppKit/NSScrollView.h>
#import <AppKit/NSClipView.h>
#import <AppKit/NSTableColumn.h>
#include "Packet.h"
#include "HostCache.h"
#include "PPPacketUIAdditons.h"
#include "MyDocument.h"
#include "OutlineViewItem.h"
#include "PacketCaptureWindowController.h"
#include "IndividualPacketWindowController.h"

static void record_expanded_items(NSOutlineView *outlineView, NSMutableDictionary *expandedItems, id <OutlineViewItem> item);
static void expand_items(NSOutlineView *outlineView, NSMutableDictionary *expandedItems, id <OutlineViewItem> item);
static OutlineViewItem *copy_item_tree(id <OutlineViewItem> root);

@implementation IndividualPacketWindowController

- (id)initWithWindowNibName:(NSString *)windowNibName
{
	if((self = [super initWithWindowNibName:windowNibName]) != nil) {
		expandedItems = [[NSMutableDictionary alloc] init];	
	}
	return self;
}

- (id)init
{
	return [self initWithPacket:nil];
}

- (id)initWithPacket:(Packet *)aPacket
{
	if((self = [self initWithWindowNibName:@"IndividualPacket"]) != nil) {
		packet = [aPacket retain];
		packetItems = copy_item_tree(packet);
		[packetItems retain];
	}
	return self;
}

- (void)windowDidLoad
{
	[packetOutlineView setDataSource:self];
	[packetHexView setDataSource:self];
	[packetOutlineView setColumnAutoresizingStyle:NSTableViewNoColumnAutoresizing];
	[[NSNotificationCenter defaultCenter] addObserver:self
	 selector:@selector(hostNameLookupCompletedNotification:)
	 name:PPHostCacheHostNameLookupCompleteNotification
	 object:[[self document] hostCache]];
}

- (NSString *)windowTitleForDocumentDisplayName:(NSString *)displayName
{
	return [NSString stringWithFormat:@"%@ - %@ - Packet #%u, %@ %@",
	displayName, [[self document] interface], [packet number],
	([packet protocols] != nil) ? [packet protocols] : @"", ([packet info] != nil) ? [packet info] : @""];
}

- (void)setDocumentEdited:(BOOL)flag
{
	/* for an individual window, do not show as being dirty/edited */
	if([self isMemberOfClass:[IndividualPacketWindowController class]])
		return;

	[super setDocumentEdited:flag];
}

- (NSResponder *)nextResponder
{
	if([self isMemberOfClass:[IndividualPacketWindowController class]])
		return [[self document] packetCaptureWindowController];

	return nil;
}

- (void)setPacket:(Packet *)aPacket
{
	NSPoint scrollPosition;

	scrollPosition = [[[packetOutlineView enclosingScrollView] contentView] bounds].origin;

	if(packet != nil)
		record_expanded_items(packetOutlineView, expandedItems, packetItems);

	[aPacket retain];
	[packet release];
	packet = aPacket;

	[packetItems release];
	packetItems = copy_item_tree(packet);
	[packetItems retain];

	[packetOutlineView reloadData];
	[packetHexView reloadData];

	expand_items(packetOutlineView, expandedItems, packetItems);

	if([[[packetOutlineView enclosingScrollView] contentView] bounds].size.height < [packetOutlineView bounds].size.height) {
		[[[packetOutlineView enclosingScrollView] contentView] scrollToPoint:scrollPosition];
		[[packetOutlineView enclosingScrollView] reflectScrolledClipView:[[packetOutlineView enclosingScrollView] contentView]];
	}
}

- (Packet *)packet
{
	return packet;
}

- (void)hostNameLookupCompletedNotification:(NSNotification *)note
{
	[self setPacket:packet];
}

/* NSOutlineView data-source methods */

- (BOOL)outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item
{
	if(item == nil) {
		if(packetItems == nil)
			return NO;
		else
			return [packetItems expandable];
	} else
		return [(id <OutlineViewItem>)item expandable];
}

- (int)outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item
{
	if(item == nil) {
		if(packetItems == nil)
			return 0;
		else
			return [packetItems numberOfChildren];
	} else
		return [(id <OutlineViewItem>)item numberOfChildren];
}

- (id)outlineView:(NSOutlineView *)outlineView child:(int)index ofItem:(id)item
{
	id ret;

	if(item == nil) {
		if(packetItems == nil)
			return nil;
		else
			ret = [packetItems childAtIndex:index];
	} else {
			ret = [(id <OutlineViewItem>)item childAtIndex:index];
	}

	return ret;
}

- (id)outlineView:(NSOutlineView *)outlineView objectValueForTableColumn:(NSTableColumn *)tableColumn byItem:(id)item
{
	BOOL isValue;

	/* Table columns are labelled "Field" and "Value",
	   the valueAtIndex stores the field at 0 and the value at 1  */

	isValue = [[tableColumn identifier] isEqualToString:@"Value"];

	if([(id <OutlineViewItem>)item numberOfValues] < (1 + (isValue ? 1 : 0)))
		return nil;

	return [(id <OutlineViewItem>)item valueAtIndex:isValue ? 1 : 0];
}

/* HexView data-source methods */

- (unsigned int)length
{
	if(packet == nil)
		return 0;

	return [[packet packetData] length];
}

- (const void *)bytes
{
	if(packet == nil)
		return NULL;

	return [[packet packetData] bytes];
}

- (void)dealloc
{
	[expandedItems release];
	[packetItems release];
	[packet release];
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	[super dealloc];
}

@end

/* XXX todo: this doesn't record expanded items if the parent is collapsed--NSOutlineView collapses
   children, but records the state elsewhere (as when the parent is expanded again, any children
   which were expanded are expanded again). shouldExpandItem/shouldCollapseItem can't be used to
   get around this because they are not called when option-clicking items. Also notifications pass
   the NSOutlineView as the notification object so are useless here. So, I can't see any way to fix
   this 100% reliably.. */

static void record_expanded_items(NSOutlineView *outlineView, NSMutableDictionary *expandedItems, id <OutlineViewItem> item)
{
	unsigned int i;

	for(i = 0; i < [item numberOfChildren]; ++i) {
		NSString *childName;
		NSMutableArray *pair; /* {BOOL isExpanded, NSMutableDictionary *childExpandedItems} */
		NSMutableDictionary *childExpandedItems;
		id <OutlineViewItem> child;
		NSNumber *isExpanded;

		child = [item childAtIndex:i];
		childName = [child valueAtIndex:0];
		isExpanded = [NSNumber numberWithBool:[outlineView isItemExpanded:child]];

		if((pair = [expandedItems objectForKey:childName]) == nil) {
			childExpandedItems = [NSMutableDictionary dictionary];
			pair = [NSMutableArray arrayWithObjects:isExpanded, childExpandedItems, nil];
			[expandedItems setObject:pair forKey:childName];
		} else {
			[pair replaceObjectAtIndex:0 withObject:isExpanded];
			childExpandedItems = [pair objectAtIndex:1];
		}

		record_expanded_items(outlineView, childExpandedItems, child);
	}
}

static void expand_items(NSOutlineView *outlineView, NSMutableDictionary *expandedItems, id <OutlineViewItem> item)
{
	unsigned int i;

	for(i = 0; i < [item numberOfChildren]; ++i) {
		NSString *childName;
		NSMutableArray *pair; /* {BOOL isExpanded, NSMutableDictionary *childExpandedItems} */
		NSMutableDictionary *childExpandedItems;
		id <OutlineViewItem> child;
		NSNumber *isExpanded;

		child = [item childAtIndex:i];
		childName = [child valueAtIndex:0];

		if((pair = [expandedItems objectForKey:childName]) == nil)
			continue;

		isExpanded = [pair objectAtIndex:0];
		childExpandedItems = [pair objectAtIndex:1];

		if([isExpanded boolValue])
			[outlineView expandItem:child];

		expand_items(outlineView, childExpandedItems, child);
	}
}

static OutlineViewItem *copy_item_tree(id <OutlineViewItem> root)
{
	unsigned int i;
	OutlineViewItem *result;

	if(root == nil || ([root numberOfValues] < 1 && [root numberOfChildren] < 1))
		return nil;

	if((result = [[OutlineViewItem alloc] init]) == nil)
		return nil;

	for(i = 0; i < [root numberOfValues]; ++i)
		[result addObject:[root valueAtIndex:i]];

	for(i = 0; i < [root numberOfChildren]; ++i) {
		id <OutlineViewItem> temp;

		if((temp = copy_item_tree([root childAtIndex:i])) == nil)
			break;

		[result addChild:temp];
	}

	return [result autorelease];
}
