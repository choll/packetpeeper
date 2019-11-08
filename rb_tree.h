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

#ifndef _RB_TREE_H_
#define _RB_TREE_H_

#define RB_NODE_RED   1
#define RB_NODE_BLACK 0

struct rb_node
{
    struct rb_node* parent;
    struct rb_node* left;
    struct rb_node* right;
    void* data;
    int colour;
    /* the key field is variable sized */
    uint8_t key[];
};

typedef int (*rb_key_comp_fptr)(const void* key_a, const void* key_b);

typedef void (*rb_node_free_fptr)(struct rb_node* node);

typedef void (*rb_key_copy_fptr)(void* dst, const void* src);

/* searches tree at root for node containing key */
struct rb_node*
rb_search(struct rb_node* root, const void* key, rb_key_comp_fptr rb_key_comp);

/* inserts node into the tree at root, and returns the (maybe new) root of
   the tree, maintains the red-black tree property. root may be NULL */
struct rb_node* rb_insert(
    struct rb_node* root, struct rb_node* node, rb_key_comp_fptr rb_key_comp);

/* counts the number of nodes in a tree */
unsigned int rb_count_tree(struct rb_node* root);

/* deletes the tree at root */
void rb_free_tree(struct rb_node* root, rb_node_free_fptr node_free);

/* deletes a node from the tree, and returns the (maybe new) root of the tree,
   maintains the red-black tree property. */
struct rb_node* rb_node_delete(
    struct rb_node* root, struct rb_node* node, rb_key_copy_fptr rb_key_copy);

#endif
