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

#ifndef _PPNODEGRAPHVIEW_H_
#define _PPNODEGRAPHVIEW_H_

#include <unistd.h>
#include <dotneato.h>
#import <AppKit/NSView.h>

@class NSString;
@class NSImage;
@class Packet;

@interface PPNodeGraphView : NSView {
	Agraph_t *graph;
	NSImage *cache;
	float zoomPercent;
}

- (void)setGraph:(Agraph_t *)graphVal;

/* private method */
- (void)calculateFrame;

- (void)setZoomPercent:(float)zoom;
- (float)zoomPercent;
- (void)resetZoom;

/*
NOV 05:

	Problem, layouts are associated with graphs,

*/




// handling init/cleanup of layouts?
// when setLayout is called, the old layout is cleaned up, the new one is initialised.

// user can do setNeedsDisplay:YES
// or, when you add a node, it will set the value of needsLayout.
// then the user can call performLayout.

//- (void)redraw;

// not better to have some data source model?
// access packets via packetAtIndex method?

//- (void)addNodeWithLabel:(NSString *)label;

//- (void)removeNodeWithLabel:(NSString *)label;
//- (void)

// what if nodes without labels needed

// layouts..
// dot, neato, fdp, twopi, circo

@end

#endif /* _PPNODEGRAPHVIEW_H_ */
