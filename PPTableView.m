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

#import <Foundation/NSIndexSet.h>
#import <AppKit/NSEvent.h>
#include "PPTableView.h"

#import <Foundation/NSString.h>

static int eventRow = -1;

@implementation NSTableView (PPTableViewAdditions)

- (int)eventRow
{
	return eventRow;
}

- (void)setEventRow:(NSEvent *)event
{
	eventRow = [self rowAtPoint:[self convertPoint:[event locationInWindow] fromView:nil]];
}

- (void)selectRowsForEvent:(NSEvent *)event
{
	if([event type] == NSRightMouseDown && ![self isRowSelected:[self eventRow]])
		[self selectRowIndexes:[NSIndexSet indexSetWithIndex:[self eventRow]] byExtendingSelection:NO];
}

@end

@implementation PPTableView

- (NSMenu *)menuForEvent:(NSEvent *)event
{
	[self setEventRow:event];
	[self selectRowsForEvent:event];
	return [super menuForEvent:event];
}

@end
