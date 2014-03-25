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


#include <inttypes.h>
#include <stdlib.h>
#include "rb_tree.h"

/* colours node red and attaches it to the tree at root, only to be used by
   insert. root may not be NULL */
static void rb_attach(struct rb_node *root, struct rb_node *node, rb_key_comp_fptr rb_key_comp);

/* fixes the red-black property of the tree at root, returning the new root of
   the tree */
static struct rb_node *rb_insert_fixup(struct rb_node *root, struct rb_node *node);

/* only called by fixup, left rotates node */
static struct rb_node *rb_rotate_left(struct rb_node *root, struct rb_node *node);

/* only called by fixup, right rotates node */
static struct rb_node *rb_rotate_right(struct rb_node *root, struct rb_node *node);

/* fixes the red-black property of the tree at root, returning the new root of
   the tree */
static struct rb_node *rb_delete_fixup(struct rb_node *root, struct rb_node *node);

static struct rb_node *rb_tree_successor(struct rb_node *node);

static struct rb_node *rb_tree_minimum(struct rb_node *node);


struct rb_node *rb_search(struct rb_node *root, const void *key, rb_key_comp_fptr key_comp)
{
    int ret;

    if(root == NULL)
        return NULL;

    ret = key_comp(root->key, key);

    if(ret > 0) /* root is greater than key */
        return rb_search(root->left, key, key_comp);

    if(ret < 0) /* root is less than key */
        return rb_search(root->right, key, key_comp);

    /* if it isnt greater or less than, then we found a match, so return it */
    return root;
}

/* inserts node into the tree at root, and returns the (maybe new) root of the tree
   Assumptions: node is not NULL. */
struct rb_node *rb_insert(struct rb_node *root, struct rb_node *node, rb_key_comp_fptr key_comp)
{
    if(root == NULL) {
        node->colour = RB_NODE_BLACK;
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        return node;
    }
    rb_attach(root, node, key_comp);
    return rb_insert_fixup(root, node);
}

/*
    Assumptions: root and node are not NULL, node does not already
    exist in root.
*/
static void rb_attach(struct rb_node *root, struct rb_node *node, rb_key_comp_fptr key_comp)
{
    /* if the root element is less than the node */
    if(key_comp(root->key, node->key) < 0) {
        if(root->right == NULL) {
            node->colour = RB_NODE_RED;
            node->right = NULL;
            node->left = NULL;
            node->parent = root;
            root->right = node;
        } else
            rb_attach(root->right, node, key_comp);
    } else { /* else the root element is greater than the node, equality is not a possiblity */
        if(root->left == NULL) {
            node->colour = RB_NODE_RED;
            node->right = NULL;
            node->left = NULL;
            node->parent = root;
            root->left = node;
        } else
            rb_attach(root->left, node, key_comp);
    }
}

/*
    We assume:
        root is non-null, node is non-null and has a valid parent (i.e
        is not the root)
*/
static struct rb_node *rb_insert_fixup(struct rb_node *root, struct rb_node *node)
{
    struct rb_node *nnephew; /* nodes 'nephew' */

    /* while property 4 is violated (a red node cannot have a red child) */
    while(node->parent != NULL && node->parent->parent != NULL && node->parent->colour == RB_NODE_RED) {
        if(node->parent == node->parent->parent->left) { /* if our parent is the left child */
            nnephew = node->parent->parent->right;
            if(nnephew != NULL && nnephew->colour == RB_NODE_RED) { /* case 1 */
                node->parent->colour = RB_NODE_BLACK;
                nnephew->colour = RB_NODE_BLACK;
                node->parent->parent->colour = RB_NODE_RED;
                node = node->parent->parent;
            } else {
                if(node == node->parent->right) { /* case 2 */
                    node = node->parent;
                    root = rb_rotate_left(root, node);
                    /* note that node is now a level lower in the tree after the rotation,
                      so is at the same overall level as before the node = node->parent */
                }
                /* case 3 */
                node->parent->colour = RB_NODE_BLACK;
                node->parent->parent->colour = RB_NODE_RED;
                root = rb_rotate_right(root, node->parent->parent);
            }
        } else { /* else our parent is the right */
            nnephew = node->parent->parent->left;
            if(nnephew != NULL && nnephew->colour == RB_NODE_RED) { /* case 1 */
                node->parent->colour = RB_NODE_BLACK;
                nnephew->colour = RB_NODE_BLACK;
                node->parent->parent->colour = RB_NODE_RED;
                node = node->parent->parent;
            } else {
                if(node == node->parent->left) { /* case 2 */
                    node = node->parent;
                    root = rb_rotate_right(root, node);
                    /* note that node is now a level lower in the tree after the rotation,
                       so is at the same overall level as before the node = node->parent */
                }
                /* case 3 */
                node->parent->colour = RB_NODE_BLACK;
                node->parent->parent->colour = RB_NODE_RED;
                root = rb_rotate_left(root, node->parent->parent);
            }
        }
    }

    root->colour = RB_NODE_BLACK;
    return root;
}

/*
    Assumptions; root is not null, node is not null, node->right is not null.
*/
static struct rb_node *rb_rotate_left(struct rb_node *root, struct rb_node *node)
{
    struct rb_node *nrchild; /* right-hand child of node */

    /* init nrchild */
    nrchild = node->right;

    /* move nrchild's left child to be node's right child */
    node->right = nrchild->left;

    /* if the new right child is a real node, update its parent */
    if(node->right != NULL)
        node->right->parent = node;

    /* node becomes nrchild's left child */
    nrchild->left = node;

    /* update parents */
    nrchild->parent = node->parent;
    node->parent = nrchild;

    /* update parents pointers to children */
    if(nrchild->parent == NULL) {
        root = nrchild; /* node was the root, so nrchild is the new root */
    } else if(nrchild->parent->left == node) { /* is nrchild its parents left child? */
        nrchild->parent->left = nrchild;
    } else { /* else nrchild must be its parents right child */
        nrchild->parent->right = nrchild;
    }

    return root;
}

/*
    Assumptions; root is not null, node is not null, node->left is not null.
*/
static struct rb_node *rb_rotate_right(struct rb_node *root, struct rb_node *node)
{
    struct rb_node *nlchild; /* left-hand child of node */

    /* init nlchild */
    nlchild = node->left;

    /* move nlchild's right child to be node's left child */
    node->left = nlchild->right;

    /* if the new left child is a real node, update its parent */
    if(node->left != NULL)
        node->left->parent = node;

    /* node becomes nlchild's right child */
    nlchild->right = node;

    /* update parents */
    nlchild->parent = node->parent;
    node->parent = nlchild;

    /* update parents pointers to children */
    if(nlchild->parent == NULL) {
        root = nlchild; /* node was the root, so nlchild is the new root */
    } else if(nlchild->parent->left == node) { /* is nlchild is its parents left child? */
        nlchild->parent->left = nlchild;
    } else { /* else nlchild must be its parents right child */
        nlchild->parent->right = nlchild;
    }

    return root;
}

unsigned int rb_count_tree(struct rb_node *root)
{
    if(root == NULL)
        return 0;

    return (1 + rb_count_tree(root->left) + rb_count_tree(root->right));
}

/*
    Assumptions: none.
*/
void rb_free_tree(struct rb_node *root, rb_node_free_fptr node_free)
{
    if(root == NULL)
        return;

    rb_free_tree(root->left, node_free);
    rb_free_tree(root->right, node_free);

    node_free(root);
}

/*
    Assumptions: node is not NULL.
*/
struct rb_node *rb_node_delete(struct rb_node *root, struct rb_node *node, rb_key_copy_fptr rb_key_copy)
{
    struct rb_node *x, *y;

    /* if node does not have two children, y = 'node' */
    if(node->left == NULL || node->right == NULL)
        y = node;
    else /* otherwise y is 'node's successor (node with smallest key greater than 'node') */
        y = rb_tree_successor(node);

    if(y->left != NULL)
        x = y->left;
    else
        x = y->right;

    if(x != NULL)
        x->parent = y->parent;

    if(y->parent == NULL)
        root = x;
    else if(y == y->parent->left)
        y->parent->left = x;
    else
        y->parent->right = x;

    /* if y is the successor of node */
    if(y != node) {
        rb_key_copy(node->key, y->key);
        node->data = y->data;
        free(y);
    } else
        free(node);

    if(x != NULL && y->colour == RB_NODE_BLACK)
        root = rb_delete_fixup(root, x);

    return root;
}

static struct rb_node *rb_delete_fixup(struct rb_node *root, struct rb_node *node)
{
    struct rb_node *w;

    while(node != root && node->colour == RB_NODE_BLACK) {
        if(node == node->parent->left) {
            w = node->parent->right;
            if(w != NULL && w->colour == RB_NODE_RED) {
                w->colour = RB_NODE_BLACK;
                node->parent->colour = RB_NODE_RED;
                root = rb_rotate_left(root, node->parent);
                w = node->parent->right;
            }
            if(w != NULL && w->left != NULL && w->right != NULL && w->left->colour == RB_NODE_BLACK && w->right->colour == RB_NODE_BLACK) {
                w->colour = RB_NODE_RED;
                node = node->parent;
            } else {
                if(w != NULL && w->right != NULL && w->right->colour == RB_NODE_BLACK) {
                    if(w->left != NULL) {
                        w->left->colour = RB_NODE_BLACK;
                        root = rb_rotate_right(root, w);
                    }
                    w = node->parent->right;
                }
                if(w != NULL)
                    w->colour = node->parent->colour;
                node->parent->colour = RB_NODE_BLACK;
                if(w != NULL && w->right != NULL)
                    w->right->colour = RB_NODE_BLACK;
                if(node->parent->right != NULL)
                    root = rb_rotate_left(root, node->parent);
                node = root;
            }
        } else {
            w = node->parent->left;
            if(w != NULL && w->colour == RB_NODE_RED) {
                w->colour = RB_NODE_BLACK;
                node->parent->colour = RB_NODE_RED;
                root = rb_rotate_right(root, node->parent);
                w = node->parent->left;
            }
            if(w != NULL && w->right != NULL && w->left != NULL && w->right->colour == RB_NODE_BLACK && w->left->colour == RB_NODE_BLACK) {
                w->colour = RB_NODE_RED;
                node = node->parent;
            } else {
                if(w != NULL && w->left != NULL && w->left->colour == RB_NODE_BLACK) {
                    if(w->right != NULL) {
                        w->right->colour = RB_NODE_BLACK;
                        root = rb_rotate_left(root, w);
                    }
                    w = node->parent->left;
                }
                if(w != NULL)
                    w->colour = node->parent->colour;
                node->parent->colour = RB_NODE_BLACK;
                if(w != NULL && w->left != NULL)
                    w->left->colour = RB_NODE_BLACK;
                if(node->parent->left != NULL)
                    root = rb_rotate_right(root, node->parent);
                node = root;
            }
        }
    }

    node->colour = RB_NODE_BLACK;

    return root;
}

static struct rb_node *rb_tree_successor(struct rb_node *node)
{
    struct rb_node *x;

    if(node->right != NULL)
        return rb_tree_minimum(node->right);

    x = node->parent;

    while(x != NULL && node == x->right) {
        node = x;
        x = x->parent;
    }

    return x;
}

static struct rb_node *rb_tree_minimum(struct rb_node *node)
{
    while(node->left != NULL)
        node = node->left;

    return node;
}
