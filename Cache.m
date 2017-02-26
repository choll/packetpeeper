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

#include <stdlib.h>
#include <string.h>
#import <Foundation/NSString.h>
#include "Cache.h"

static void rb_node_free(struct rb_node *node);

@implementation Cache

- (id)init
{
	return nil;
}

- (id)initWithKeySize:(unsigned int)key_sz hashSlots:(unsigned int)islots hashFunction:(key_hash_fptr)hashFunc comparisonFunction:(rb_key_comp_fptr)compFunc
{
	unsigned int i;

	if((self = [super init]) != nil) {
		if((nslots = islots) == 0 || key_sz == 0 || (htable = malloc(nslots * sizeof(struct rb_node *))) == NULL) {
			[super dealloc];
			return nil;
		}

		for(i = 0; i < nslots; ++i)
			htable[i] = NULL;

		node_sz = sizeof(struct rb_node) + key_sz;
		[self setHashFunction:hashFunc];
		[self setComparisonFunction:compFunc];
	}
	return self;
}

- (void)setHashFunction:(key_hash_fptr)hashFunc
{
	key_hash = hashFunc;
}

- (void)setComparisonFunction:(rb_key_comp_fptr)compFunc
{
	key_comp = compFunc;
}

- (id)objectForKey:(const void *)key
{
	struct rb_node *result;

	if((result = rb_search(htable[key_hash(key)], key, key_comp)) != NULL)
		return result->data;

	return nil;
}

- (BOOL)insertObject:(id)object forKey:(const void *)key
{
	struct rb_node *node;
	unsigned int i;

	if(object == nil || (node = malloc(node_sz)) == NULL)
		return NO;

	node->data = [object retain];

	(void)memcpy(node->key, key, (node_sz - sizeof(struct rb_node)));

	i = key_hash(key);
	htable[i] = rb_insert(htable[i], node, key_comp);

	return YES;
}

- (void)flush
{
	unsigned int i;

	for(i = 0; i < nslots; ++i) {
		rb_free_tree(htable[i], rb_node_free);
		htable[i] = NULL;
	}
}

- (void)dealloc
{
	[self flush];
	free(htable);
	[super dealloc];
}

@end

static void rb_node_free(struct rb_node *node)
{
	[(id)node->data release];
	free(node);
}

