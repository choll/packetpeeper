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

#include <dotneato.h>
#import <Foundation/NSString.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSData.h>
#import <AppKit/NSBezierPath.h>
#import <AppKit/NSImage.h>
#import <AppKit/NSBitmapImageRep.h>
#import <AppKit/NSColor.h>
#include "quartzgen.h"
#include "PPNodeGraphView.h"

extern char *Info[]; /* defined by graphviz */
static GVC_t *gvc = NULL;

@implementation PPNodeGraphView

- (id)initWithFrame:(NSRect)rect
{
	if((self = [super initWithFrame:rect]) != nil) {
		cache = nil;
		zoomPercent = 100.0f;
	}
    return self;
}

- (void)setGraph:(Agraph_t *)graphVal
{
	if(gvc == NULL) {
		gvc = gvNEWcontext(Info, username());
		gvc->codegen = &QPDF_CodeGen;
	}

	graph = graphVal;
	gvBindContext(gvc, graph);
}

- (void)calculateFrame
{
	NSSize size;
	float scale;

	scale = zoomPercent / 100.0f;

// gvc.bb ?
// GD_bb(gvc->g).UR.

	size.width = GD_bb(graph).UR.x * scale;
	size.height = GD_bb(graph).UR.y * scale;

	[self setFrameSize:size];
}

// ok... when something is already zoomed in, and the layout
// changes and it is redrawn, it looks fine. until you touch the
// zoom slider, at which point it becomes super zoomed in.

- (void)setZoomPercent:(float)zoom
{
	[self resetZoom];
	zoomPercent = zoom;
	zoom /= 100.0f;
	[self scaleUnitSquareToSize:NSMakeSize(zoom, zoom)];
	[self setNeedsDisplay:YES];
}

- (float)zoomPercent
{
	return zoomPercent;
}

- (void)resetZoom
{
	[self scaleUnitSquareToSize:[self convertSize:NSMakeSize(1.0f, 1.0f) fromView: nil]];
	zoomPercent = 100.0f;
	[self setNeedsDisplay:YES];
}

- (void)drawRect:(NSRect)rect {
	gvrender_job_t job;
//	NSSize size;

//	size.width = 2.0;
//	size.height = 2.0;

//	[self scaleUnitSquareToSize:size];
	// soo.... scaling

// need to blank the area 1st

	if(needLayout) {

		job.output_file = NULL;
		gvc->job = &job;

		// we can write to the context pdf data, then make a pdf image
		// rep from that.

// pass in the graphics context somehow...

	/* need to fully initialise gvc structure */
//		gvc->zoom = 20.0;
//		gvc->scale = 2.0;
//	GD_drawing(gvc->g)->scale = 2; // this should be passed to begin_page
	// why is the drawing null...
//	gvc->size.x,y

/*

[self lockFocus];

NSBitmapImageRep *bits;
bits = [[NSBitmapImageRep alloc]
           initWithFocusedViewRect: [self bounds]];
[self unlockFocus];
*/


// zoom and scale ignored here, but works if set manually in quartzgen.
// has problems with components overlapping - why?
// if you make a generic ZoomView, it could be useful in future.
// WHY IS IT SUDDENLY WORKING WITH ZOOM?!?!
// STOPS WORKING IF LEFT FOR A WHILE... context becomes invalid?

//		[self ];
//		[[NSColor blueColor] set];
//		[NSBezierPath fillRect:[self bounds]];

// on the second draw the bounds width are increased- why?
// setting springs fixes this, but breaks drawing...

//		[[NSColor whiteColor] set];
//		[NSBezierPath fillRect:[self bounds]];

// is some optimisation being done to prevent the box being drawn?


		emit_graph(gvc, EMIT_SORTED);
		emit_reset(gvc);



	[self lockFocus];

	[cache release];

	cache = [[NSImage alloc] init]; //initWithData:


	[cache addRepresentation:[[[NSBitmapImageRep alloc] initWithFocusedViewRect:[self bounds]] autorelease]];

//[cache addRepresentation:[self bitmapImageRepForCachingDisplayInRect:[self frame]]];

//	[cache setDataRetained:YES];

// self bounds does not work because we've only been asked to
// display a smaller portion
// data taken by pdf methods is not actual vector data, but raster..
// is it possible to draw into a pdf?

	[self unlockFocus];



	} else {

//		NSLog(@"result = %d", [cache drawInRect:rect]);

		NSLog(@" width = %f, height = %f", rect.size.width, rect.size.height);
		NSLog(@" x origin = %f, y origin = %f", rect.origin.x, rect.origin.y);

// why is the view being asked to draw the whole screen?

		[cache drawInRect:rect fromRect:rect operation:NSCompositeCopy fraction:1.0f];

		// display the cache
		// the cache should
		// be set to some value in the init method,
		// because it sets needLayout to no.


// ok, both the cache and no cache give 50fps performance, perhaps there is some cap?
// test on the ibook.

// on ibook, no cache gives under 10fps, doesnt quite make it to the notch before 10.
// with cache, gives between 10 and 20fps, typically just around the nothc before 20,
// makes it to 20 when the view needs scrolling. which would suggest even better performance
// when the graph is larger.

	}
}

// A zoom function... should it be exponential?
// Snap at the middle?
// Should the window have a status bar?
// A pop-up showing the zoom percent?

- (void)dealloc
{
// cleanup on gvc?
	graph_cleanup[layout](graph);

	[cache release];
	[super dealloc];
}

@end

// more than one way to give a node graph... could just show the nodes as was planned,
// or the other method, which showed the nodes on the lan, and who they accessed...?
// PERHAPS... have `primary' nodes as those with a mac-address...
// quite a lot of ways of doing this..
// for now concentrate on a basic mode, show all the connections, this would be especially cool to connect to
// the mirror port of a switch on a big-ish network...
