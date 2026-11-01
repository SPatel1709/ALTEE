/*
	ABAC AVP parsing methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/string.h>
#include <linux/slab.h>
#include "avp.h"

void destroy_avp_list(avp *head) 
{
	// Free the avp linked list given by head
	avp* cursor = head;
	avp* to_free = NULL;
	while (cursor != NULL) {
		kfree(cursor->name);
		kfree(cursor->value);
		to_free = cursor;
		cursor = cursor->next;
		if (to_free) kfree(to_free);
	}
}

int findidx(char *buffer, char ch, int start, int end)
{
	// Find the index of first occurance of ch in buffer between start and end (excluding end)
	int i = start;
	for (i = start; i < end; i++) {
		if (buffer[i] == ch)
			return i;
	}
	return -1;
}

avp *parse_avp(char *buffer, int start, int end)
{
	int pair_delim;
	int name_start;
	int name_len;
	int value_len;
	avp *p;

	if (!buffer || start >= end)
		return NULL;

	pair_delim = findidx(buffer, '=', start, end);
	if (pair_delim <= start || pair_delim >= end - 1)
		return NULL;

	p = kcalloc(1, sizeof(*p), GFP_KERNEL);
	if (!p)
		return NULL;

	name_start = start;
	if (pair_delim - start > 4 &&
	    strncmp(buffer + start, "tee:", 4) == 0) {
		p->tee_protected = true;
		name_start += 4;
	}

	name_len = pair_delim - name_start;
	value_len = end - pair_delim - 1;
	p->name = kcalloc(name_len + 1, sizeof(char), GFP_KERNEL);
	p->value = kcalloc(value_len + 1, sizeof(char), GFP_KERNEL);
	if (!p->name || !p->value) {
		kfree(p->name);
		kfree(p->value);
		kfree(p);
		return NULL;
	}

	memcpy(p->name, buffer + name_start, name_len);
	memcpy(p->value, buffer + pair_delim + 1, value_len);
	p->name[name_len] = '\0';
	p->value[value_len] = '\0';
	return p;
}

avp *parse_avp_section(char *buffer, int start, int end)
{
	// Parse the string between | delimiters
	// Example: Designation=Professor,Department=CSE
	int _start = start;
	int delim = findidx(buffer, ',', _start, end);
	avp *cursor, *head;
	cursor = NULL;
	head = NULL;
	while (delim != -1 && _start < end) {
		if (cursor) {
			cursor->next = parse_avp(buffer, _start, delim);
			cursor = cursor->next;
		} else {
			head = parse_avp(buffer, _start, delim);
			cursor = head;
		}
		_start = delim + 1;
		delim = findidx(buffer, ',', _start, end);
	}
	// if there was more than one avp, then there will be one more avp between the last , and |
	if (cursor) {
		cursor->next = parse_avp(buffer, _start, end);
	} else {
		head = parse_avp(buffer, _start, end);
		cursor = head;
	}
	return head;
}
