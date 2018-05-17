/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_parser.h>
#include <msgpack.h>
#include "onigmo.h"

#include "regexp.h"

static void delete_rules(struct regexp_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct regexp_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct regexp_rule, _head);
        flb_free(rule->regex_pattern);
        flb_free(rule->replacement);
        flb_regex_destroy(rule->regex);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}


/* string escaping */
static int json_escape_str(const char *str, int len, unsigned char **out_buf, size_t *out_size)
{
    unsigned char * buf = flb_malloc(len * 2 * sizeof(unsigned char));
    int pos = 0, start_offset = 0;
    int out_len = 0;
	unsigned char c;
	while (len--)
	{
		c = str[pos];
		switch(c)
		{
        case '"':
            memcpy((unsigned char *)buf + out_len, "\\\"", 2);
            out_len += 2;
            break;
        case '\\':
			memcpy((unsigned char *)buf + out_len, "\\\\", 2);
            out_len += 2;
            break;
		default:
            memcpy((unsigned char *)buf + out_len, str + start_offset, 1);
            out_len++;
		}
        start_offset = ++pos;
    }
    memcpy((unsigned char *)buf + out_len, "\0", 1);
    *out_size = out_len + 1;
    *out_buf = buf;
    return 0;
}

static int set_rules(struct regexp_ctx *ctx, struct flb_filter_instance *f_ins)
{
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_config_prop *prop;
    struct regexp_rule *rule;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        /* Create a new rule */
        rule = flb_malloc(sizeof(struct regexp_rule));
        if (!rule) {
            flb_errno();
            return -1;
        }

        /* Get the type */
        if (strcasecmp(prop->key, "substitude") == 0) {
            rule->type = REGEXP_SUBST;
        }
        else {
            delete_rules(ctx);
            flb_free(rule);
            return -1;
        }

        /* As a value we expect a pair of field name and a regular expression */
        split = flb_utils_split(prop->val, ' ', 1);
        if (mk_list_size(split) != 2) {
            flb_error("[filter_regexp] invalid configuraion format, expected regular expression and replacement");
            delete_rules(ctx);
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        /* Get first value (field) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        rule->regex_pattern = flb_strndup(sentry->value, sentry->len);

        /* Get remaining content (regular expression) */
        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        rule->replacement = flb_strndup(sentry->value, sentry->len);
        rule->replacement_len = strlen(rule->replacement);

        /* Release split */
        flb_utils_split_free(split);

        /* Convert string to regex pattern */
        rule->regex = flb_regex_create((unsigned char *) rule->regex_pattern);
        if (!rule->regex) {
            delete_rules(ctx);
            flb_free(rule);
            return -1;
        }

        /* Link to parent list */
        mk_list_add(&rule->_head, &ctx->rules);
    }

    return 0;
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int regexp_replace_data(struct regexp_rule *rule, char *val, size_t vlen, unsigned char **out_buf, size_t *out_size)
{
    unsigned char *start, *range, *end;
    ssize_t ret;
    OnigRegion *region = onig_region_new();

    const long multiplier = 2;

    int allocate = vlen * multiplier;
    int allocated = 0;
    unsigned char *replaced = flb_malloc(allocate * sizeof(unsigned char));
    unsigned char *tmp_ptr;
    allocated = allocate;

    unsigned long offset = 0;
    unsigned long len = 0;
    while (true)
    {
        end = (unsigned char *)val + (vlen - offset);
        range = end;
        start = (unsigned char *)val;
        ret = onig_search(rule->regex->regex, (unsigned char *)val, end, start, range, region, ONIG_OPTION_NONE);
        /* we have got a match */
        if (ret >= 0)
        {
            if (allocated < vlen + rule->replacement_len)
            {
                allocate = (vlen + rule->replacement_len) * multiplier;
                tmp_ptr = flb_realloc(replaced, allocate * sizeof(unsigned char));
                if (!tmp_ptr)
                {
                    flb_error("[in_regexp] could not allocate memory");
                    flb_free(replaced);
                }
                replaced = tmp_ptr;
                allocated = allocate;
            }
            memcpy((unsigned char *)replaced + len, (unsigned char *)start, region->beg[DEFAULT_INDEX] * sizeof(unsigned char));
            len += region->beg[DEFAULT_INDEX];
            memcpy((unsigned char *)replaced + len, (unsigned char *)rule->replacement, rule->replacement_len * sizeof(unsigned char) );
            offset += region->end[DEFAULT_INDEX];
            len += rule->replacement_len;
            val = val + region->end[DEFAULT_INDEX];
        }
        else if (ret == ONIG_MISMATCH)
        {
            break;
            ret = FLB_FILTER_NOTOUCH;
        }
        else
        { /* error */
            OnigUChar s[ONIG_MAX_ERROR_MESSAGE_LEN];
            onig_error_code_to_str(s, ret);
            fprintf(stderr, "ERROR: %s\n", s);
            return -1;
        }
    }

    onig_region_free(region, 0 /* 1:free self, 0:free contents only */);
    // Add any text after the last match
    if (offset < vlen)
    {
        if (allocated < len + (vlen - offset))
        {
            allocate = len + (vlen - offset);
            tmp_ptr = flb_realloc(replaced, allocate * sizeof(unsigned char));
            if (!tmp_ptr)
            {
                flb_error("[in_regexp] could not allocate memory");
                flb_free(replaced);
            }
            replaced = tmp_ptr;
        }
        memcpy((unsigned char *)replaced + len, (unsigned char *)val, (vlen - offset) * sizeof(unsigned char));
        len += vlen - offset;
        offset = 0;
    }

    onig_region_free(region, 1 /* 1:free self, 0:free contents only */);
    *out_buf = replaced;
    *out_size = len;
    return FLB_FILTER_MODIFIED;
}

static int cb_regexp_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct regexp_ctx *ctx;

    /* Create context */
    ctx = flb_malloc(sizeof(struct regexp_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->rules);

    /* Load rules */
    ret = set_rules(ctx, f_ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int msgpackobj2char(msgpack_object *obj,
                           char **ret_char, int *ret_char_size)
{
    int ret = -1;

    if (obj->type == MSGPACK_OBJECT_STR) {
        *ret_char      = (char*)obj->via.str.ptr;
        *ret_char_size = obj->via.str.size;
        ret = 0;
    }
    else if (obj->type == MSGPACK_OBJECT_BIN) {
        *ret_char      = (char*)obj->via.bin.ptr;
        *ret_char_size = obj->via.bin.size;
        ret = 0;
    }

    return ret;
}

static int cb_regexp_filter(void *data, size_t bytes,
                            char *tag, int tag_len,
                            void **ret_buf, size_t *ret_size,
                            struct flb_filter_instance *f_ins,
                            void *context,
                            struct flb_config *config)
{
    int ret = FLB_FILTER_NOTOUCH;
    int jret = 0;
    unsigned long i = 0;
    msgpack_unpacked result;
    size_t off = 0;
    (void)f_ins;
    (void)config;
    struct flb_time tm;
    msgpack_object *obj;
    int map_num;
    unsigned char * out_buf;
    unsigned char * json_buf;
    unsigned long json_size;
    size_t out_size;
    struct regexp_ctx *ctx = context;

    msgpack_object_kv *kv;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    struct mk_list *head;
    struct regexp_rule *rule;
    struct mpk_kv *kv_map;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off))
    {
        out_buf = NULL;
        if (result.data.type != MSGPACK_OBJECT_ARRAY)
        {
            continue;
        }
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        if (obj->type == MSGPACK_OBJECT_MAP)
        {
            map_num = obj->via.map.size;
            // msgpack_object_print(stdout, *obj);
            // fprintf(stdout, "\n");
            kv_map = flb_malloc(map_num * sizeof(struct mpk_kv));

            for (i = 0; i < map_num; i++)
            {
                kv = &obj->via.map.ptr[i];

                kv_map[i].key = &kv->key;

                if (msgpackobj2char(&kv->val, &kv_map[i].val, &kv_map[i].vlen) < 0)
                {
                    /* val is not string */
                    continue;
                }
                /* Lookup parser */
                mk_list_foreach(head, &ctx->rules)
                {
                    rule = mk_list_entry(head, struct regexp_rule, _head);

                    ret = regexp_replace_data(rule, kv_map[i].val, kv_map[i].vlen,
                                              (unsigned char **)&out_buf, &out_size);

                    if (out_buf[0] == '{')
                    {
                        jret = json_escape_str(out_buf, out_size, (unsigned char **)&json_buf, &json_size);
                        kv_map[i].val = json_buf;
                        kv_map[i].vlen = json_size;
                        free(out_buf);
                    }
                    else
                    {
                        kv_map[i].val = out_buf;
                        kv_map[i].vlen = out_size;
                    }
                }
            }
        }

        if (ret == FLB_FILTER_MODIFIED)
        {
            msgpack_pack_array(&tmp_pck, 2);
            flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

            msgpack_pack_map(&tmp_pck, map_num);
            for (i = 0; i < map_num; i++) {
                msgpack_pack_object(&tmp_pck, *kv_map[i].key);
                msgpack_pack_str(&tmp_pck, kv_map[i].vlen);
                msgpack_pack_str_body(&tmp_pck, kv_map[i].val, kv_map[i].vlen);
                flb_free(kv_map[i].val);
            }
        }
        else
        {
            /* re-use original data*/
            msgpack_pack_object(&tmp_pck, result.data);
        }
        flb_free(kv_map);
        kv_map = NULL;
        msgpack_unpacked_destroy(&result);
    }

    /* link new buffers */
    *ret_buf = tmp_sbuf.data;
    *ret_size = tmp_sbuf.size;
    return ret;
}


static int cb_regexp_exit(void *data, struct flb_config *config)
{
    struct regexp_ctx *ctx = data;

    delete_rules(ctx);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_regexp_plugin = {
    .name         = "regexp",
    .description  = "regexp events by specified field values",
    .cb_init      = cb_regexp_init,
    .cb_filter    = cb_regexp_filter,
    .cb_exit      = cb_regexp_exit,
    .flags        = 0
};
