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

@class NSTimer;

/* FDP is not included in the interface; it seems to cause a bug in the graph lib.
   Its probably not worth looking for, as moving the class to Agraph is likely. */
enum _graph_layout {LAYOUT_DOT, LAYOUT_NEATO, LAYOUT_FDP, LAYOUT_TWOPI, LAYOUT_CIRCO};
typedef enum _graph_layout graph_layout;

@interface PPNodeGraphController : NSObject {
	NSTimer *timer;
	Agraph_t *graph;
	graph_layout layout;
	BOOL needLayout;
}

- (graph_layout)layout;
- (void)setLayout:(graph_layout)aLayout;
- (void)performLayout;

- (void)addNode:(NSString *)name;
/* private method */
- (Agnode_t *)node:(NSString *)name;
- (BOOL)nodeExists:(NSString *)name;
- (void)removeNode:(NSString *)name;
- (void)addEdgeFrom:(NSString *)src to:(NSString *)dst label:(NSString *)label;
- (BOOL)edgeExistsFrom:(NSString *)src to:(NSString *)dst;
- (void)removeEdgeFrom:(NSString *)src to:(NSString *)dst;

- (void)addPacket:(Packet *)packet;
- (void)addPacketArray:(NSArray *)packetArray;
- (void)removePacket:(Packet *)packet;
- (void)reset;

@end

/*
Controller must notify the window controller of changes
it will then set a timer for updates.

Should the view have the GVC_t? it binds it to the graph,
and sets layout etc. This way multiple views w/ different
view would be possible. Do this, even though multiple views
of the same graph are not a feature.

So the view needs some initWithGraph method.

where should the timer be... well, it should be in the controller.
But, the stream reassembly windows... should there really be multiple
duplicate windows?

*/
