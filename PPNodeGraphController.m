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

#include "PPNodeGraphController.h"

Agnode_t *agNEWnode(Agraph_t *, char *, Agnode_t *);
void agINSnode(Agraph_t *, Agnode_t *);
void agDELnode(Agraph_t *, Agnode_t *);
Agedge_t *agNEWedge(Agraph_t *, Agnode_t *, Agnode_t *, Agedge_t *);
void agINSedge(Agraph_t *, Agedge_t *);
void agDELedge(Agraph_t *, Agedge_t *);

typedef void (*graph_layout_fptr)(Agraph_t *);

static const graph_layout_fptr graph_layout[] = {dot_layout,
												 neato_layout,
												 fdp_layout,
												 twopi_layout,
												 circo_layout};

typedef void (*graph_cleanup_fptr)(Agraph_t *);

static const graph_cleanup_fptr graph_cleanup[] = {dot_cleanup,
												   neato_cleanup,
												   fdp_cleanup,
												   twopi_cleanup,
												   circo_cleanup};

@implementation PPNodeGraphController

// init
		layout = LAYOUT_DOT;
		needLayout = YES;

- (graph_layout)layout
{
	return layout;
}

- (void)setLayout:(graph_layout)aLayout
{
	if(layout != aLayout) {
		graph_cleanup[layout](graph);
		layout = aLayout;
		needLayout = YES;
		[self setNeedsDisplay:YES];
	}
}

- (void)performLayout
{
	graph_layout[layout](graph);
	[self calculateFrame];
	needLayout = NO;
}

- (void)addNode:(NSString *)name
{
	Agnode_t *node;

	node = [self node:name];

	// modify shape
}

- (Agnode_t *)node:(NSString *)name
{
	Agnode_t *node;
	char *strname;

	strname = (char *)[name UTF8String];

    if((node = agfindnode(graph, strname)) == NULL) {
		node = agNEWnode(graph, strname, graph->proto->n);
		dtinsert(graph->univ->node_dict, node);
		agINSnode(graph, node);
		needLayout = YES;
    }

	return node;
}

- (BOOL)nodeExists:(NSString *)name
{
	return (agfindnode(graph, (char *)[name UTF8String]) != NULL);
}

- (void)removeNode:(NSString *)name
{
	Agnode_t *node;

	if((node = agfindnode(graph, (char *)[name UTF8String])) != NULL) {
		agDELnode(graph, node);
		needLayout = YES;
	}
}

- (void)addEdgeFrom:(NSString *)src to:(NSString *)dst label:(NSString *)label
{
	Agedge_t *edge;
	Agnode_t *tail,
			 *head;

	/* assumes the graph is both strict and directed,
	   creates src and dst if needed */

	tail = [self node:src];
	head = [self node:dst];

	//NSLog(@"tail = %p, head = %p", tail, head);

	graph->proto->e->head = head; // needed?
	graph->proto->e->tail = tail;

	if(agfindedge(graph, tail, head) == NULL) {
		NSLog(@"new edge between %@ and %@", src, dst);
		edge = agNEWedge(graph, tail, head, graph->proto->e);
		agINSedge(graph, edge);
		graph->proto->e->head = graph->proto->e->tail = graph->proto->n;
		edge->printkey = 0;
		needLayout = YES;
	}

}

- (BOOL)edgeExistsFrom:(NSString *)src to:(NSString *)dst
{
	Agnode_t *tail,
			 *head;

	if((tail = agfindnode(graph, (char *)[src UTF8String])) == NULL ||
	   (head = agfindnode(graph, (char *)[dst UTF8String])) == NULL)
		return NO;

	return (agfindedge(graph, tail, head) != NULL);
}

- (void)removeEdgeFrom:(NSString *)src to:(NSString *)dst
{
	Agedge_t *edge;
	Agnode_t *tail,
			 *head;

	if((tail = agfindnode(graph, (char *)[src UTF8String])) == NULL ||
	   (head = agfindnode(graph, (char *)[dst UTF8String])) == NULL)
		return;

	if((edge = agfindedge(graph, tail, head)) != NULL)
		agDELedge(graph, edge);
}


- (void)dealloc
{
	graph_cleanup[layout](graph);
	[super dealloc];
}

@end

#if 0
		aginit(); // aginit needs to be done only once per process, no?
		// needs to be moved.

		/* create a strict, directed graph with no name */
		if((graph = agopen("", AGDIGRAPHSTRICT)) == NULL) {
			[super dealloc];
			return nil;
		}
		
			(void)agclose(graph);
#endif