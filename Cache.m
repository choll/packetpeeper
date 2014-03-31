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
#import <Foundation/NSArchiver.h>
#include "Cache.h"

static void encode_tree(NSCoder *coder, struct rb_node *root, unsigned int key_sz);
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

- (void)encodeWithCoder:(NSCoder *)coder
{
	unsigned int i;
	unsigned int sum;	/* total sum of the sizes of the red-black trees */

	sum = 0;

	for(i = 0; i < nslots; ++i)
		sum += rb_count_tree(htable[i]);

	[coder encodeValueOfObjCType:@encode(unsigned int) at:&nslots];
	[coder encodeValueOfObjCType:@encode(unsigned int) at:&sum];
	[coder encodeValueOfObjCType:@encode(unsigned int) at:&node_sz];

	for(i = 0; i < nslots; ++i)
		encode_tree(coder, htable[i], node_sz - sizeof(struct rb_node));
}

- (id)initWithCoder:(NSCoder *)coder
{
	unsigned int i, sum, hval;
	struct rb_node *node;

	/* This is potentially dangerous, in that we trust the input from the
	   serialized data, when perhaps we should not trust it. This may result
	   in us reading in too much or too little data. However, NSCoder doesnt
	   seem to contain any features to allow this to be avoided. */

	if((self = [super init]) != nil) {
		[coder decodeValueOfObjCType:@encode(unsigned int) at:&nslots];
		[coder decodeValueOfObjCType:@encode(unsigned int) at:&sum];
		[coder decodeValueOfObjCType:@encode(unsigned int) at:&node_sz];

		if(nslots == 0 || node_sz == 0 || (htable = malloc(nslots * sizeof(struct rb_node *))) == NULL) {
			[super dealloc];
			return nil;
		}

		for(i = 0; i < nslots; ++i)
			htable[i] = NULL;

		while(sum--) {
			/* yes, a malloc for every node is highly inefficient, but allocating
			   the memory all at once is not workable. A possible solution would be
			   for Cache to have its own custom memory allocator, but for now
			   it's a malloc for every node. */
			if((node = malloc(node_sz)) == NULL) {
				[self dealloc];
				return nil;
			}
			node->data = [[coder decodeObject] retain];
			[coder decodeArrayOfObjCType:@encode(unsigned char) count:node_sz - sizeof(struct rb_node) at:node->key];
			hval = key_hash(node->key);
			htable[hval] = rb_insert(htable[hval], node, key_comp);
		}
	}
	return self;
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

static void encode_tree(NSCoder *coder, struct rb_node *root, unsigned int key_sz)
{
	if(root == NULL)
		return;

	[coder encodeObject:root->data];
	[coder encodeArrayOfObjCType:@encode(unsigned char) count:key_sz at:root->key];

	encode_tree(coder, root->left, key_sz);
	encode_tree(coder, root->right, key_sz);
}

static void rb_node_free(struct rb_node *node)
{
	[(id)node->data release];
	free(node);
}
