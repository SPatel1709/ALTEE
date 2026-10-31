/*
	Compiled ABAC policy tree methods
*/

#include <linux/slab.h>
#include <linux/string.h>
#include "avp.h"
#include "policy.h"



// siblings are denoted by *next as for a parent maintaining **ptr for children is difficult.
struct abac_effect_leaf {
	enum abac_effect effect;
	struct abac_effect_leaf *next;
};

struct abac_match_node {
	avp *user;
	avp *env;
	struct abac_effect_leaf *effects;
	struct abac_match_node *next;
};

struct abac_op_bucket {
	enum abac_op op;
	struct abac_match_node *matches;
	struct abac_op_bucket *next;
};

struct abac_obj_bucket {
	avp *object;
	struct abac_op_bucket *ops;
	struct abac_obj_bucket *next;
};

struct abac_policy_tree {
	struct abac_obj_bucket *objects;
};

static avp *clone_avp_list(avp *src)
{
	avp *head = NULL;
	avp *tail = NULL;
	avp *node;

	while (src != NULL) {
		node = kcalloc(1, sizeof(avp), GFP_KERNEL);
		node->name = kstrdup(src->name, GFP_KERNEL);
		node->value = kstrdup(src->value, GFP_KERNEL);
		if (!head) {
			head = node;
			tail = node;
		} else {
			tail->next = node;
			tail = node;
		}
		src = src->next;
	}
	return head;
}

static bool avp_list_contains(avp *required, avp *actual)
{
	avp *r_cursor = required;
	avp *a_cursor;
	bool match_found;

	while (r_cursor != NULL) {
		a_cursor = actual;
		match_found = false;
		while (a_cursor != NULL) {
			if (strcmp(r_cursor->name, a_cursor->name) == 0 &&
			    strcmp(r_cursor->value, a_cursor->value) == 0) {
				match_found = true;
				break;
			}
			a_cursor = a_cursor->next;
		}
		if (!match_found)
			return false;
		r_cursor = r_cursor->next;
	}
	return true;
}

static bool avp_list_equal(avp *left, avp *right)
{
	return avp_list_contains(left, right) && avp_list_contains(right, left);
}

static bool compare_op(enum abac_op rule_op, enum abac_op access_op,
		       enum abac_effect effect)
{
	if (rule_op == access_op)
		return true;
	if (effect == ABAC_ALLOW && rule_op == ABAC_MODIFY &&
	    access_op == ABAC_READ)
		return true;
	return false;
}

static struct abac_obj_bucket *find_object_bucket(struct abac_policy_tree *tree,avp *object)
{
	struct abac_obj_bucket *bucket = tree->objects;

	while (bucket != NULL) {
		if (avp_list_equal(bucket->object, object))
			return bucket;
		bucket = bucket->next;
	}
	return NULL;
}

static struct abac_op_bucket *find_op_bucket(struct abac_obj_bucket *bucket,
					      enum abac_op op)
{
	struct abac_op_bucket *cursor = bucket->ops;

	while (cursor != NULL) {
		if (cursor->op == op)
			return cursor;
		cursor = cursor->next;
	}
	return NULL;
}

static struct abac_match_node *find_match_node(struct abac_op_bucket *bucket,
						avp *user, avp *env)
{
	struct abac_match_node *cursor = bucket->matches;

	while (cursor != NULL) {
		if (avp_list_equal(cursor->user, user) &&
		    avp_list_equal(cursor->env, env))
			return cursor;
		cursor = cursor->next;
	}
	return NULL;
}

static void append_effect(struct abac_match_node *match,
			  enum abac_effect effect)
{
	struct abac_effect_leaf *cursor = match->effects;
	struct abac_effect_leaf *leaf;

	while (cursor != NULL) {
		if (cursor->effect == effect)
			return;
		if (!cursor->next)
			break;
		cursor = cursor->next;
	}

	leaf = kcalloc(1, sizeof(*leaf), GFP_KERNEL);
	leaf->effect = effect;
	if (!match->effects)
		match->effects = leaf;
	else
		cursor->next = leaf;
}

struct abac_policy_tree *build_policy_tree(abac_rule *rules)
{
	struct abac_policy_tree *tree;
	struct abac_obj_bucket *obj_bucket;
	struct abac_op_bucket *op_bucket;
	struct abac_match_node *match;
	abac_rule *rule = rules;

	tree = kcalloc(1, sizeof(*tree), GFP_KERNEL);
	while (rule != NULL) {
		obj_bucket = find_object_bucket(tree, rule->object);
		if (!obj_bucket) {
			obj_bucket = kcalloc(1, sizeof(*obj_bucket), GFP_KERNEL);
			obj_bucket->object = clone_avp_list(rule->object);

			// we are adding the sibling at the head.
			obj_bucket->next = tree->objects;
			tree->objects = obj_bucket;
		}

		op_bucket = find_op_bucket(obj_bucket, rule->op);
		if (!op_bucket) {
			op_bucket = kcalloc(1, sizeof(*op_bucket), GFP_KERNEL);
			op_bucket->op = rule->op;
			op_bucket->next = obj_bucket->ops;
			obj_bucket->ops = op_bucket;
		}

		match = find_match_node(op_bucket, rule->user, rule->env);
		if (!match) {
			match = kcalloc(1, sizeof(*match), GFP_KERNEL);
			match->user = clone_avp_list(rule->user);
			match->env = clone_avp_list(rule->env);
			match->next = op_bucket->matches;
			op_bucket->matches = match;
		}
		append_effect(match, rule->effect);
		rule = rule->next;
	}
	return tree;
}

void destroy_policy_tree(struct abac_policy_tree *tree)
{
	struct abac_obj_bucket *obj_bucket;
	struct abac_obj_bucket *obj_next;
	struct abac_op_bucket *op_bucket;
	struct abac_op_bucket *op_next;
	struct abac_match_node *match;
	struct abac_match_node *match_next;
	struct abac_effect_leaf *effect;
	struct abac_effect_leaf *effect_next;

	if (!tree)
		return;

	obj_bucket = tree->objects;
	while (obj_bucket != NULL) {
		obj_next = obj_bucket->next;
		destroy_avp_list(obj_bucket->object);
		op_bucket = obj_bucket->ops;
		while (op_bucket != NULL) {
			op_next = op_bucket->next;
			match = op_bucket->matches;
			while (match != NULL) {
				match_next = match->next;
				destroy_avp_list(match->user);
				destroy_avp_list(match->env);
				effect = match->effects;
				while (effect != NULL) {
					effect_next = effect->next;
					kfree(effect);
					effect = effect_next;
				}
				kfree(match);
				match = match_next;
			}
			kfree(op_bucket);
			op_bucket = op_next;
		}
		kfree(obj_bucket);
		obj_bucket = obj_next;
	}
	kfree(tree);
}

bool resolve_policy_tree(struct abac_policy_tree *tree, avp *uattr, avp *oattr,avp *env, enum abac_op op)
{
	struct abac_obj_bucket *obj_bucket;
	struct abac_op_bucket *op_bucket;
	struct abac_match_node *match;
	struct abac_effect_leaf *effect;
	bool allow_found = false;

	if (!tree)
		return false;

	obj_bucket = tree->objects;
	while (obj_bucket != NULL) {
		if (!avp_list_contains(obj_bucket->object, oattr)) {
			obj_bucket = obj_bucket->next;
			continue;
		}
		op_bucket = obj_bucket->ops;
		while (op_bucket != NULL) {
			match = op_bucket->matches;
			while (match != NULL) {
				if (!avp_list_contains(match->user, uattr)) {
					match = match->next;
					continue;
				}
				if (match->env) {
					if (!env || !avp_list_contains(match->env, env)) {
						match = match->next;
						continue;
					}
				}
				effect = match->effects;
				while (effect != NULL) {
					if (compare_op(op_bucket->op, op, effect->effect)) {
						if (effect->effect == ABAC_DENY)
							return false;
						allow_found = true;
					}
					effect = effect->next;
				}
				match = match->next;
			}
			op_bucket = op_bucket->next;
		}
		obj_bucket = obj_bucket->next;
	}
	return allow_found;
}
