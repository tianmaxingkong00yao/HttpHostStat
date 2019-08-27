#pragma once

#define RB_RED 1
#define RB_BLACK 0

#define rbt_is_red(node) ((node)->color == RB_RED)

typedef struct _rbtree_node
{
	struct _rbtree_node *left;
	struct _rbtree_node *right;
	struct _rbtree_node *parent;
	int color;
} rbtree_node_t;

typedef void(*rbtree_insert_cb)(rbtree_node_t *root, rbtree_node_t *node, rbtree_node_t *sentinel);
typedef struct
{
	rbtree_node_t *root;
	rbtree_node_t *sentinel; /* 哨兵 */
	rbtree_insert_cb insert;
} rbtree_t;

static _inline void 
rbtree_init(rbtree_t *tree, rbtree_node_t *sentinel, rbtree_insert_cb insert)
{
	sentinel->color = RB_BLACK;
	tree->root = sentinel;
	tree->sentinel = sentinel;
	tree->insert = insert;
}

static _inline rbtree_node_t *
rbtree_min(rbtree_node_t *node, rbtree_node_t *sentinel)
{
	while (node->left != sentinel)
	{
		node = node->left;
	}

	return node;
}

void rbtree_insert(rbtree_t *tree, rbtree_node_t *node);

void rbtree_delete(rbtree_t *tree, rbtree_node_t *node);

void rbtree_insert_value(rbtree_node_t *root, rbtree_node_t *node, rbtree_node_t *sentinel);
