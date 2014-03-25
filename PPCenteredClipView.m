/*
 * Packet Peeper
 * Copyright 2006, 2007, Chris E. Holloway
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

#include <math.h>
#import <Foundation/NSString.h>
#import <AppKit/NSScrollView.h>
#import <AppKit/NSColor.h>
#include "PPCenteredClipView.h"

/*
	Based on Brock Brandenberg's SBCenteringClipView:
	http://www.bergdesign.com/missing_cocoa_docs/nsclipview.html
*/

@implementation PPCenteredClipView

- (id)initWithScrollView:(NSScrollView *)scrollview
{
	NSClipView *oldClip;

	if((self = [super initWithFrame:[[scrollview contentView] frame]]) != nil) {
		oldClip = [scrollview contentView];

		[self setDocumentView:[oldClip documentView]];
		[scrollview setContentView:self];
        
		/* stops the document view being drawn in the top corner as well as the center.. */
		[scrollview setDrawsBackground: NO];

		[self setBackgroundColor:[NSColor windowBackgroundColor]];
		[self setDrawsBackground:YES];
	}
	return self;
}

- (void)centerDocument
{
	NSRect docRect;
	NSRect clipRect;

	docRect = [[self documentView] frame];
	clipRect = [self bounds];

	if(docRect.size.width < clipRect.size.width)
		clipRect.origin.x = roundf((docRect.size.width - clipRect.size.width) / 2.0f);

	if(docRect.size.height < clipRect.size.height)
		clipRect.origin.y = roundf((docRect.size.height - clipRect.size.height) / 2.0f);

	[self scrollToPoint:clipRect.origin];
}

- (NSPoint)constrainScrollPoint:(NSPoint)proposedNewOrigin
{
	float xmax, ymax;
	NSRect docRect;
	NSRect clipRect;

	docRect = [[self documentView] frame];
	clipRect = [self bounds];

	xmax = docRect.size.width - clipRect.size.width;
	ymax = docRect.size.height - clipRect.size.height;

	if(docRect.size.width < clipRect.size.width)
		proposedNewOrigin.x = roundf(xmax / 2.0f);
	else
		proposedNewOrigin.x = roundf(MAX(0.0f, MIN(proposedNewOrigin.x, xmax)));

	if(docRect.size.height < clipRect.size.height)
		proposedNewOrigin.y = roundf(ymax / 2.0f);
	else
		proposedNewOrigin.y = roundf(MAX(0.0f, MIN(proposedNewOrigin.y, ymax)));

	return proposedNewOrigin;
}

//- (void)viewBoundsChanged:(NSNotification *)notification
//{
//	[super viewBoundsChanged:notification];
//}

//- (void)viewFrameChanged:(NSNotification *)notification
//{
//	[super viewFrameChanged:notification];
//}

- (void)setFrame:(NSRect)frameRect
{
	[super setFrame:frameRect];
	[self centerDocument];
}

- (void)setFrameOrigin:(NSPoint)newOrigin
{
	[super setFrameOrigin:newOrigin];
	[self centerDocument];
}

- (void)setFrameSize:(NSSize)newSize
{
	[super setFrameSize:newSize];
	[self centerDocument];
}

- (void)setFrameRotation:(CGFloat)angle
{
	[super setFrameRotation:angle];
	[self centerDocument];
}

@end
