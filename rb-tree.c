#include <stdint.h>
#include "rb-tree.h"

static void 
rbtree_left_rotate(rbtree_node_t **root, rbtree_node_t *sentinel, 
	rbtree_node_t *node)
{
	rbtree_node_t *tmp;
	
	tmp = node->right;
	node->right = tmp->left;

	if (tmp->left != sentinel) {
		tmp->left->parent = node;
	}

	tmp->parent = node->parent;

	if (node == *root) {
		*root = tmp;
	}
	else if (node == node->parent->left) {
		node->parent->left = tmp;
	}
	else {
		node->parent->right = tmp;
	}

	tmp->left = node;
	node->parent = tmp;
}

static void 
rbtree_right_rotate(rbtree_node_t **root, rbtree_node_t *sentinel, 
	rbtree_node_t *node)
{
	rbtree_node_t *tmp;

	tmp = node->left;
	node->left = tmp->right;

	if (tmp->right != sentinel) {
		tmp->right->parent = node;
	}

	tmp->parent = node->parent;

	if (node == *root) {
		*root = tmp;
	}
	else if (node == node->parent->right) {
		node->parent->right = tmp;
	}
	else {
		node->parent->left = tmp;
	}

	tmp->right = node;
	node->parent = tmp;
}

void 
rbtree_insert(rbtree_t *tree, rbtree_node_t *node)
{
	rbtree_node_t **root, *tmp, *sentinel;

	root = &tree->root;
	sentinel = tree->sentinel;

	if (*root == sentinel) {
		node->parent = NULL;
		node->left = sentinel;
		node->right = sentinel;
		node->color = RB_BLACK;
		*root = node;

		return;
	}

	tree->insert(*root, node, sentinel);

	while (node != *root && rbt_is_red(node->parent)) {

		if (node->parent == node->parent->parent->left) {
			tmp = node->parent->parent->right;

			if (rbt_is_red(tmp)) {
				node->parent->color = RB_BLACK;
				tmp->color = RB_BLACK;
				node->parent->parent->color = RB_RED;
				node = node->parent->parent;
			}
			else {
				if (node == node->parent->right) {
					node = node->parent;
					rbtree_left_rotate(root, sentinel, node);
				}

				node->parent->color = RB_BLACK;
				node->parent->parent->color = RB_RED;
				rbtree_right_rotate(root, sentinel, node->parent->parent);
			}
		}
		else {
			tmp = node->parent->parent->left;

			if (rbt_is_red(tmp)) {
				node->parent->color = RB_BLACK;
				tmp->color = RB_BLACK;
				node->parent->parent->color = RB_RED;
				node = node->parent->parent;
			}
			else {
				if (node == node->parent->left) {
					node = node->parent;
					rbtree_right_rotate(root, sentinel, node);
				}

				node->parent->color = RB_BLACK;
				node->parent->parent->color = RB_RED;
				rbtree_left_rotate(root, sentinel, node->parent->parent);
			}
		}

	}

	(*root)->color = RB_BLACK;
}

void
rbtree_delete(rbtree_t *tree, rbtree_node_t *node)
{
	uintptr_t red;
	rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

	/* a binary tree delete */

	root = &tree->root;
	sentinel = tree->sentinel;

	if (node->left == sentinel) {
		temp = node->right;
		subst = node;

	}
	else if (node->right == sentinel) {
		temp = node->left;
		subst = node;

	}
	else {
		subst = rbtree_min(node->right, sentinel);

		if (subst->left != sentinel) {
			temp = subst->left;
		}
		else {
			temp = subst->right;
		}
	}

	if (subst == *root) {
		*root = temp;
		temp->color = RB_BLACK;

		/* DEBUG stuff */
		node->left = NULL;
		node->right = NULL;
		node->parent = NULL;
		
		return;
	}

	red = rbt_is_red(subst);

	if (subst == subst->parent->left) {
		subst->parent->left = temp;

	}
	else {
		subst->parent->right = temp;
	}

	if (subst == node) {

		temp->parent = subst->parent;

	}
	else {

		if (subst->parent == node) {
			temp->parent = subst;

		}
		else {
			temp->parent = subst->parent;
		}

		subst->left = node->left;
		subst->right = node->right;
		subst->parent = node->parent;
		subst->color = node->color;

		if (node == *root) {
			*root = subst;

		}
		else {
			if (node == node->parent->left) {
				node->parent->left = subst;
			}
			else {
				node->parent->right = subst;
			}
		}

		if (subst->left != sentinel) {
			subst->left->parent = subst;
		}

		if (subst->right != sentinel) {
			subst->right->parent = subst;
		}
	}

	/* DEBUG stuff */
	node->left = NULL;
	node->right = NULL;
	node->parent = NULL;

	if (red) {
		return;
	}

	/* a delete fixup */

	while (temp != *root && temp->color == RB_BLACK) {

		if (temp == temp->parent->left) {
			w = temp->parent->right;

			if (rbt_is_red(w)) {
				w->color = RB_BLACK;
				temp->parent->color = RB_RED;
				rbtree_left_rotate(root, sentinel, temp->parent);
				w = temp->parent->right;
			}

			if (w->left->color == RB_BLACK && w->right->color == RB_BLACK) {
				w->color = RB_RED;
				temp = temp->parent;

			}
			else {
				if (w->right->color == RB_BLACK) {
					w->left->color = RB_BLACK;
					w->color = RB_RED;
					rbtree_right_rotate(root, sentinel, w);
					w = temp->parent->right;
				}

				w->color = temp->parent->color;
				temp->parent->color = RB_BLACK;
				w->right->color = RB_BLACK;
				rbtree_left_rotate(root, sentinel, temp->parent);
				temp = *root;
			}

		}
		else {
			w = temp->parent->left;

			if (w->color == RB_RED) {
				w->color = RB_BLACK;
				temp->parent->color = RB_RED;
				rbtree_right_rotate(root, sentinel, temp->parent);
				w = temp->parent->left;
			}

			if (w->left->color == RB_BLACK && w->right->color == RB_BLACK) {
				w->color = RB_RED;
				temp = temp->parent;

			}
			else {
				if (w->left->color == RB_BLACK) {
					w->right->color = RB_BLACK;
					w->color = RB_RED;
					rbtree_left_rotate(root, sentinel, w);
					w = temp->parent->left;
				}

				w->color = temp->parent->color;
				temp->parent->color = RB_BLACK;
				w->left->color = RB_BLACK;
				rbtree_right_rotate(root, sentinel, temp->parent);
				temp = *root;
			}
		}
	}

	temp->color = RB_BLACK;
}
