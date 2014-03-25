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

#ifndef _CACHE_H_
#define _CACHE_H_

#import <Foundation/NSObject.h>
#include "rb_tree.h"

/*
	returns an index into the hash table, from 0 to the specified number of slots - 1
*/
typedef unsigned int (*key_hash_fptr)(const void *key);

@interface Cache : NSObject <NSCoding>
{
	/* the hash table */
	struct rb_node **htable;

	/* given a pointer to the supplied key data, returns an integer between 0 and table_sz - 1 */
	key_hash_fptr key_hash;

	/* given a pointer to the supplied key data, returns a value to be used in testing for equality */
	rb_key_comp_fptr key_comp;

	/* the size in bytes of a node */
	unsigned int node_sz;

	/* the number of hash table slots */
	unsigned int nslots;
}

- (id)initWithKeySize:(unsigned int)key_sz hashSlots:(unsigned int)islots hashFunction:(key_hash_fptr)hashFunc comparisonFunction:(rb_key_comp_fptr)compFunc;

- (void)setHashFunction:(key_hash_fptr)hashFunc;

- (void)setComparisonFunction:(rb_key_comp_fptr)compFunc;

/* returns the object corresponding to the given key */
- (id)objectForKey:(const void *)key;

/* inserts object using the value for key, key must not already have been added */
- (BOOL)insertObject:(id)object forKey:(const void *)key;

- (void)flush;

@end

#endif /* _CACHE_H_ */
