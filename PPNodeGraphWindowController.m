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

#import <Foundation/NSString.h>
#import <AppKit/NSScrollView.h>
#import <AppKit/NSPopUpButton.h>
#import <AppKit/NSColor.h>
#include "MyDocument.h"
#include "PPNodeGraphView.h"
#include "PPCenteredClipView.h"
#include "PPNodeGraphWindowController.h"

@implementation PPNodeGraphWindowController

- (id)init
{
	if((self = [super initWithWindowNibName:@"PPNodeGraphPanel"]) != nil) {

	}
	return self;
}

// seem to be getting some kind of overdrawing effect on the arrow between nodes,
// i.e. previous contents are not being cleared before drawing.

// and a drawing in the top right... whyyyyyyyyyyyyy
// changing the springs in IB effects this..

/*
	Would some node graph controller be appropriate?
	Adding packet code to NodeGraphView is a no-no, probably same for the window controller.
	So, something to add a packet to a nodegraphview is needed...
	Would a controller be worth it, for a few lines of code...
	perhaps mydoc needs some `process packet' method.
	
	well, we cant split the model and view in this case, because.
	cos nothing...
	.
	.
	PPNodeGraphWindowController should be given a graph, and not own it itself? Yes.
	The same problem with `catch up' occurs for node graph and streams...
	Do you go for memory or snappiness.
	
	Well, how much memory does a graph take? Is it a lot? I doubt it.
	So, make a PPNodeGraphController.
	And rename PPTCPStreams to PPTCPStreamController?

	Document -> GraphController -> GraphWindow -> GraphView

	Document adds packets to the controller.
	The controller stores these packets in its internal graph structures.
	The graph window
	Well... maybe the window controller can do the work of the graph controller?
	Its a pain cos using libgraph doesnt lend itself to a modular design.
	Perhaps you could make an OO version of graphviz... or just take the code and
	make something that works for you.

	This would be a total rewrite, so... not really a good idea :)

*/

- (void)windowDidLoad
{
	PPCenteredClipView *newClipView;
	NSScrollView *scrollView;

	[[self document] setNodeGraphController:nil];

	scrollView = [nodeGraph enclosingScrollView];
	newClipView = [[PPCenteredClipView alloc] initWithScrollView:scrollView];
	[newClipView release];
/*
	newClipView = [[PPCenteredClipView alloc] initWithFrame:[[scrollView contentView] frame]];
	[nodeGraph retain];
	[scrollView setContentView:newClipView];
	[scrollView setDocumentView:nodeGraph];
	[newClipView release];
	[nodeGraph release];
	[scrollView setDrawsBackground:NO];
*/

//	[nodeGraph addEdgeFrom:@"Test1" to:@"Test2" label:nil];
//	[nodeGraph addEdgeFrom:@"Test2" to:@"Test3" label:nil];
//	[nodeGraph addEdgeFrom:@"Test3" to:@"Test4" label:nil];

	NSLog(@"Nodegraph = %p", nodeGraph);
}

- (NSString *)windowTitleForDocumentDisplayName:(NSString *)displayName
{
	return [NSString stringWithFormat:@"%@ (%@), Node Graph", [[self document] interface], displayName];
}

- (void)setDocumentEdited:(BOOL)flag
{
	return;
}

- (IBAction)layoutPopUpButton:(id)sender
{
	NSLog(@"sender = %@", sender);
	[nodeGraph setLayout:[[sender selectedItem] tag]];
}

- (IBAction)zoomSlider:(id)sender
{
	[nodeGraph setZoomPercent:[sender floatValue]];
}

- (void)dealloc
{
	[[self document] setNodeGraph:nil];
	[super dealloc];
}

@end
