/*
 * Packet Peeper
 * Copyright 2007, Chris E. Holloway
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
 
 /*
add packets, read packets
only virtual packets come out of here.

IP... source port, destination port.

*/

#include <stdlib.h>
#import <Foundation/NSObject.h>
#import <Foundation/NSData.h>
#include "Describe.h"
#include "Packet.h"
#include "IPV4Decode.h"
#include "rb_tree.h"
#include "PPIPDefragger.h"

static unsigned int frag_hash(const struct frag_id *f_id);
static int frag_comp(const void *key_a, const void *key_b);

struct frag_id {
	struct in_addr src;
	struct in_addr dst;
	uint16_t ident;
};

struct frag_data {
	NSMutableData *buf;
	NSDate *date;
};

/* does v6 use fragments? yes.... so need to make this work with ipv6 too.. */

@implementation PPIPDefragger

- (id)init
{
	unsigned int i;

	if((self = [super init])  != nil) {
		for(i = 0; i < PPIPDEFRAGGER_HTABLE_SZ; ++i)
			htable[i] = NULL;
	}
	return self;
}

- (void)addPacket:(Packet *)packet
{
	struct rb_node *result;
	struct frag_data *f_data;
	IPV4Decode *ip;
	unsigned int i;
	struct frag_id f_id;

	if(packet == nil || (ip = [packet decoderForClass:[IPV4Decode class]]) == nil)
		return;

	if([ip dontFragmentFlag] || (![ip moreFragmentsFlag] && [ip fragmentOffset] == 0))
		return;

	i = frag_hash(&f_id);

	if((result = rb_search(htable[i], &f_id, frag_comp)) == NULL) {
		if((result = malloc(sizeof(struct rb_node) + sizeof(struct frag_id))) == NULL)
			return;

		if((f_data = malloc(sizeof(struct frag_data))) == NULL) {
			free(result);
			return;
		}

		if((f_data->buf = [[NSMutableData alloc] init]) == nil) {
			free(result);
			free(f_data);
			return;
		}

		f_data->date = [[packet date] retain];

		result->data = f_data;
		*(struct frag_id *)result->key = f_id;
		htable[i] = rb_insert(htable[i], result, frag_comp);
		NSLog(@"New fragment, %@", [ip info]);
	} else {
		NSLog(@"Found fragment, %@", [ip info]);
//		f_data = result->data;
		// found it, we're already reassembling now.
	}

/* ok, so now we have a linked list of frags... well, no. we dont need a linked list, there should not be any collision.
unless something is stale... so keep a timestamp of when 1st frag was recieved. if too long has passed, delete. perioidcally
scan the tree for stale? No, only if/when it reaches a certain limit... eg we count the number of pending defragmentation
efforts, if this reaches too high a number, scan for stale entries. then what if none are deleted..? possibly could have
resource starvation attack? */



// fragment offset
// total length? is this the total length of the defraged packet, or the total length of this fragment?

// identification field identifies (zomg) a packet, i.e. each frag has the same ident
// so, combined with src and dst port, we have our 'key'.

// `more frags' bit is set for all fragments except the last fragment.
// fragment offset contains the offsst of this fragment from the beginning of the original datagram.

// if more frags is not set, and offset is not zero, is this guaranteed not to be a fragment?
// i.e. can the following occur;
//
// [ ............ whole pkt ............]
// [        frag      ][      frag2     ]
//
// pkt would be sent twice, so, no.
//
//
// how to implement flushing stale data?
}

- (void)addPacketArray:(NSArray *)array
{

}

- (Packet *)readPacket
{
	return nil;
}

- (BOOL)packetsAvailable
{
	return NO;
}

- (void)flush
{
	unsigned int i;

	for(i = 0; i < PPIPDEFRAGGER_HTABLE_SZ; ++i) {
		rb_free_tree(htable[i], free);
		htable[i] = NULL;
	}
}

- (void)dealloc
{
	[self flush];
	[super dealloc];
}

@end

static unsigned int frag_hash(const struct frag_id *f_id)
{
/*
	return (s_id->alpha.addr.s_addr & PPTCPSTREAMS_ADDR_HASHMASK)
		 + (s_id->alpha.port & PPTCPSTREAMS_PORT_HASHMASK)
		 + (s_id->beta.addr.s_addr & PPTCPSTREAMS_ADDR_HASHMASK)
		 + (s_id->beta.port & PPTCPSTREAMS_PORT_HASHMASK);
*/
	return 0;
}

static int frag_comp(const void *key_a, const void *key_b)
{
/*
	struct stream_id *id_a,
					 *id_b;

	id_a = (struct stream_id *)key_a;
	id_b = (struct stream_id *)key_b;

	if(MAX(id_a->alpha.addr.s_addr, id_a->beta.addr.s_addr) <
	   MAX(id_b->alpha.addr.s_addr, id_b->beta.addr.s_addr)) {
		return -1;
	} else if(MAX(id_a->alpha.addr.s_addr, id_a->beta.addr.s_addr) >
			  MAX(id_b->alpha.addr.s_addr, id_b->beta.addr.s_addr)) {
		return 1;
	} else if(MIN(id_a->alpha.addr.s_addr, id_a->beta.addr.s_addr) <
			  MIN(id_b->alpha.addr.s_addr, id_b->beta.addr.s_addr)) {
		return -1;
	} else if(MIN(id_a->alpha.addr.s_addr, id_a->beta.addr.s_addr) >
			  MIN(id_b->alpha.addr.s_addr, id_b->beta.addr.s_addr)) {
		return 1;
	} else if(MAX(id_a->alpha.port, id_a->beta.port) <
			  MAX(id_b->alpha.port, id_b->beta.port)) {
		return -1;
	} else if(MAX(id_a->alpha.port, id_a->beta.port) >
			  MAX(id_b->alpha.port, id_b->beta.port)) {
		return 1;
	} else if(MIN(id_a->alpha.port, id_a->beta.port) <
			  MIN(id_b->alpha.port, id_b->beta.port)) {
		return -1;
	} else if(MIN(id_a->alpha.port, id_a->beta.port) >
			  MIN(id_b->alpha.port, id_b->beta.port)) {
		return 1;
	}
*/
	return 0;
}
