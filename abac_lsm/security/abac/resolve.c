/*
	ABAC access resolution methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include "resolve.h"
#include "policy.h"
#include "avp.h"
#include "user.h"
#include "obj.h"
#include "abacfs.h"
#include "tee_bridge.h"
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#define ABAC_USER_HASH_BITS 8
#define ABAC_OBJ_HASH_BITS 10

static DEFINE_HASHTABLE(abac_user_map, ABAC_USER_HASH_BITS);
static DEFINE_HASHTABLE(abac_obj_map, ABAC_OBJ_HASH_BITS);

static u32 abac_obj_key(const char *path)
{
	return jhash(path, strlen(path), 0);
}

void abac_destroy_lookup_maps(void)
{
	abac_user *u_cursor = user_attr;
	abac_obj *o_cursor = obj_attr;

	while (u_cursor != NULL) {
		if (!hlist_unhashed(&u_cursor->hnode))
				hlist_del_init(&u_cursor->hnode);

		u_cursor = u_cursor->next;
	}

	while (o_cursor != NULL) {
		if (!hlist_unhashed(&o_cursor->hnode))
				hlist_del_init(&o_cursor->hnode);

		o_cursor = o_cursor->next;
	}
}

void abac_rebuild_lookup_maps(void)
{
	abac_user *u_cursor = user_attr;
	abac_obj *o_cursor = obj_attr;

	abac_destroy_lookup_maps();
	hash_init(abac_user_map);
	hash_init(abac_obj_map);

	while (u_cursor != NULL) {
		INIT_HLIST_NODE(&u_cursor->hnode);
		hash_add(abac_user_map, &u_cursor->hnode, u_cursor->uid);
		u_cursor = u_cursor->next;
	}

	while (o_cursor != NULL) {
		INIT_HLIST_NODE(&o_cursor->hnode);
		hash_add(abac_obj_map, &o_cursor->hnode,abac_obj_key(o_cursor->path));
		o_cursor = o_cursor->next;
	}
}

static bool avp_contains(avp *required, avp *actual)
{
	avp *r_cursor = required;
	avp *a_cursor;
	bool match_found;

	while (r_cursor != NULL) {
		a_cursor = actual;
		match_found = false;
		while (a_cursor != NULL) {
			if (strcmp(r_cursor->name, a_cursor->name) == 0 && strcmp(r_cursor->value, a_cursor->value) == 0) {
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


static bool tee_section_matches(avp *required, avp *actual,abac_tee_u32 attribute_type,abac_tee_rule_data_t *request)
{
        avp *required_cursor;
        avp *actual_cursor;
        abac_tee_attribute_t *tee_attribute;
        bool matched;

        required_cursor = required;
        while (required_cursor) {
                matched = false;
                actual_cursor = actual;

                while (actual_cursor) {
                        if (strcmp(required_cursor->name,actual_cursor->name) == 0 &&
                            (required_cursor->tee_protected || strcmp(required_cursor->value,actual_cursor->value) == 0)) {
                                matched = true;
                                break;
                        }
                        actual_cursor = actual_cursor->next;
                }

                if (!matched)
                        return false;

                if (required_cursor->tee_protected) {
                        if (request->attribute_count >= ABAC_TEE_MAX_ATTRIBUTES)
                                return false;

                        tee_attribute =&request->attributes[request->attribute_count];

                        tee_attribute->type = attribute_type;
                        if (strscpy(tee_attribute->name,required_cursor->name,sizeof(tee_attribute->name)) < 0)
                                return false;
                        if (strscpy(tee_attribute->value,actual_cursor->value,sizeof(tee_attribute->value)) < 0)
                                return false;

                        request->attribute_count++;
                }

                required_cursor = required_cursor->next;
        }

        return true;
}

static bool op_matches(enum abac_op rule_op, enum abac_op access_op,enum abac_effect effect)
{
	if (rule_op == access_op)
		return true;
	if (effect == ABAC_ALLOW && rule_op == ABAC_MODIFY && access_op == ABAC_READ)
		return true;
	return false;
}


// Returns attributes assigned to a User.
static avp *get_user_avp(unsigned int UID, abac_user *head)
{
	abac_user *hashed;
	abac_user *cursor = head;

	if (abac_use_hashmap) {
		hash_for_each_possible(abac_user_map, hashed, hnode, UID) {
			if (hashed->uid == UID)
				return hashed->attrs;
		}
		return NULL;
	}

	// We are deliberately checking all the Buckets is User not found in it's Bucket.
	while (cursor != NULL) {
		if (cursor->uid == UID) {
			return cursor->attrs;
		}
		cursor = cursor->next;
	}
	return NULL;
}

// Returns attributes assigned to File/Folder.
static avp *get_obj_avp(char *path, abac_obj *head)
{
	abac_obj *hashed;
	abac_obj *cursor = head;

	if (abac_use_hashmap) {
		u32 key = abac_obj_key(path);

		hash_for_each_possible(abac_obj_map, hashed, hnode, key) {
			if (strcmp(path, hashed->path) == 0)
				return hashed->attrs;
		}
		return NULL;
	}

	while (cursor != NULL) {
		if (strcmp(path, cursor->path) == 0) {
			return cursor->attrs;
		}
		cursor = cursor->next;
	}
	return NULL;
}

static avp *clone_avp_node(avp *src)
{
	avp *node = kcalloc(1, sizeof(*node), GFP_KERNEL);

	if (!node)
		return NULL;
	node->name = kstrdup(src->name, GFP_KERNEL);
	node->value = kstrdup(src->value, GFP_KERNEL);
	if (!node->name || !node->value) {
		kfree(node->name);
		kfree(node->value);
		kfree(node);
		return NULL;
	}
	return node;
}

static bool merge_one_avp(avp **head, avp *src)
{
	avp *cursor = *head;
	avp *node;
	char *new_value;

	while (cursor != NULL) {
		if (strcmp(cursor->name, src->name) == 0) {
			new_value = kstrdup(src->value, GFP_KERNEL);
			if (!new_value)
				return false;
			kfree(cursor->value);
			cursor->value = new_value;
			return true;
		}
		cursor = cursor->next;
	}

	node = clone_avp_node(src);
	if (!node)
		return false;
	node->next = *head;
	*head = node;
	return true;
}

static bool merge_avp_list(avp **dst, avp *src)
{
	while (src != NULL) {
		if (!merge_one_avp(dst, src))
			return false;
		src = src->next;
	}
	return true;
}

static avp *get_inherited_obj_avp(char *path, abac_obj *head)
{
	avp *merged = NULL;
	avp *attrs;
	char *prefix;
	int i;
	int path_len;

	if (!path || path[0] != '/')
		return NULL;

	path_len = strlen(path);
	if (path_len >= PATH_MAX)
		return NULL;

	if (path_len == 1) {
		attrs = get_obj_avp(path, head);
		if (!attrs)
			return NULL;
		if (!merge_avp_list(&merged, attrs)) {
			destroy_avp_list(merged);
			return NULL;
		}
		return merged;
	}

	prefix = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!prefix)
		return NULL;

	for (i = 1; i < path_len; i++) {
		if (path[i] != '/')
			continue;
		strncpy(prefix, path, i);
		prefix[i] = '\0';
		attrs = get_obj_avp(prefix, head);
		if (!attrs)
			continue;
		if (!merge_avp_list(&merged, attrs)) {
			destroy_avp_list(merged);
			kfree(prefix);
			return NULL;
		}
	}

	attrs = get_obj_avp(path, head);
	if (attrs && !merge_avp_list(&merged, attrs)) {
		destroy_avp_list(merged);
		kfree(prefix);
		return NULL;
	}

	kfree(prefix);
	return merged;
}

bool abac_resolve_linear(unsigned int UID, char *path, int mask)
{
        enum abac_op op = convert_to_abac_op(mask);
        abac_tee_rule_data_t *tee_request = NULL;
        avp *uattr;
        avp *oattr;
        abac_rule *rule;
        bool attributes_match;
        bool allow_found = false;

        if (op == ABAC_IGNORE)
                return true;

        uattr = get_user_avp(UID, user_attr);
        if (!uattr)
                return false;

        oattr = get_inherited_obj_avp(path, obj_attr);
        if (!oattr)
                return false;

        if (!policy)
                goto deny;

        if (abac_tee_mode == ABAC_TEE_ON) {
                tee_request = kzalloc(sizeof(*tee_request), GFP_KERNEL);
                if (!tee_request)
                        goto deny;
        }

        rule = policy->rules;
        while (rule) {
                if (!op_matches(rule->op, op, rule->effect)) {
                        rule = rule->next;
                        continue;
                }

                if (abac_tee_mode == ABAC_TEE_ON) {
                        memset(tee_request, 0, sizeof(*tee_request));
                        tee_request->rule_id = rule->id;

                        attributes_match = tee_section_matches(rule->object, oattr,ABAC_TEE_OBJECT_ATTRIBUTE,tee_request)
										&& tee_section_matches(rule->user, uattr,ABAC_TEE_USER_ATTRIBUTE,tee_request)
										&& tee_section_matches(rule->env, env_attr,ABAC_TEE_ENV_ATTRIBUTE,tee_request);

                        if (!attributes_match) {
                                rule = rule->next;
                                continue;
                        }

                        if (tee_request->attribute_count > 0 &&
                            !abac_tee_evaluate_rule(tee_request)) {
                                rule = rule->next;
                                continue;
                        }
                } else {
                        if (!avp_contains(rule->object, oattr) || !avp_contains(rule->user, uattr) ||
								(rule->env && (!env_attr || !avp_contains(rule->env, env_attr)))) {
                                rule = rule->next;
                                continue;
                        }
                }

                if (rule->effect == ABAC_DENY)
                        goto deny;

                allow_found = true;
                rule = rule->next;
        }

        kfree(tee_request);
        destroy_avp_list(oattr);
        return allow_found;

deny:
        kfree(tee_request);
        destroy_avp_list(oattr);
        return false;
}

bool abac_resolve_tree(unsigned int UID, char *path, int mask)
{
	enum abac_op op = convert_to_abac_op(mask);
	avp *uattr;
	avp *oattr;

	if (op == ABAC_IGNORE)
		return true;

	uattr = get_user_avp(UID, user_attr);
	if (!uattr)
		return false;

	oattr = get_inherited_obj_avp(path, obj_attr);
	if (!oattr) {
		/* A protected but unlabelled object fails closed. */
            return false;
	}

	if (!policy || !policy->tree)
		goto deny;

	{
		bool allowed = resolve_policy_tree(policy->tree, uattr, oattr, env_attr,
						 op);
		destroy_avp_list(oattr);
		return allowed;
	}

deny:
	destroy_avp_list(oattr);
	return false;
}

bool abac_resolve(unsigned int UID, char *path, int mask)
{
	if (abac_mode == ABAC_RESOLVE_LINEAR)
		return abac_resolve_linear(UID, path, mask);
	return abac_resolve_tree(UID, path, mask);
}
