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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>
#include "onigmo.h"

#include "regexp.h"

static void delete_rules(struct regexp_ctx *ctx) {
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

static int set_rules(struct regexp_ctx *ctx,
                     struct flb_filter_instance *f_ins) {
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
        } else if (strcasecmp(prop->key, "skip") == 0) {
            rule->type = REGEXP_SKIP;
        } else {
            delete_rules(ctx);
            flb_free(rule);
            return -1;
        }

        /* As a value we expect a pair of field name and a regular expression */
        split = flb_utils_split(prop->val, ' ', 1);
        if (mk_list_size(split) != 2 && rule->type != REGEXP_SKIP) {
            flb_error(
                "[filter_regexp] invalid configuraion format, expected regular "
                "expression and replacement");
            delete_rules(ctx);
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        /* Get first value (field) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        rule->regex_pattern = flb_strndup(sentry->value, sentry->len);

        if (rule->type == REGEXP_SUBST) {
            /* Get remaining content (regular expression) */
            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
            rule->replacement = flb_strndup(sentry->value, sentry->len);
            rule->replacement_len = strlen(rule->replacement);
        }

        /* Release split */
        flb_utils_split_free(split);

        /* Convert string to regex pattern */
        rule->regex = flb_regex_create((unsigned char *)rule->regex_pattern);
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
static inline int regexp_replace_data(struct regexp_rule *rule, char *val,
                                      size_t vlen, unsigned char **out_buf,
                                      size_t *out_size) {
    unsigned char *start, *range, *end;
    ssize_t ret;
    OnigRegion *region = onig_region_new();

    const long multiplier = 1;

    int allocate = vlen * multiplier;
    int allocated = 0;
    unsigned char *replaced = flb_malloc(allocate * sizeof(unsigned char));
    unsigned char *tmp_ptr;
    allocated = allocate;

    unsigned long offset = 0;
    unsigned long len = 0;
    while (true) {
        end = (unsigned char *)val + (vlen - offset);
        range = end;
        start = (unsigned char *)val;
        ret = onig_search(rule->regex->regex, (unsigned char *)val, end, start,
                          range, region, ONIG_OPTION_NONE);
        /* we have got a match */
        if (ret >= 0) {
            if (allocated < vlen + rule->replacement_len) {
                allocate = (vlen + rule->replacement_len) * multiplier;
                tmp_ptr =
                    flb_realloc(replaced, allocate * sizeof(unsigned char));
                if (!tmp_ptr) {
                    flb_error("[in_regexp] could not allocate memory");
                    flb_free(replaced);
                }
                replaced = tmp_ptr;
                allocated = allocate;
            }
            memcpy((unsigned char *)replaced + len, (unsigned char *)start,
                   region->beg[DEFAULT_INDEX] * sizeof(unsigned char));
            len += region->beg[DEFAULT_INDEX];
            memcpy((unsigned char *)replaced + len,
                   (unsigned char *)rule->replacement,
                   rule->replacement_len * sizeof(unsigned char));
            offset += region->end[DEFAULT_INDEX];
            len += rule->replacement_len;
            val = val + region->end[DEFAULT_INDEX];
        } else if (ret == ONIG_MISMATCH) {
            break;
            ret = FLB_FILTER_NOTOUCH;
        } else { /* error */
            OnigUChar s[ONIG_MAX_ERROR_MESSAGE_LEN];
            onig_error_code_to_str(s, ret);
            fprintf(stderr, "ERROR: %s\n", s);
            return -1;
        }
    }

    onig_region_free(region, 0 /* 1:free self, 0:free contents only */);
    // Add any text after the last match
    if (offset < vlen) {
        if (allocated < len + (vlen - offset)) {
            allocate = len + (vlen - offset);
            tmp_ptr = flb_realloc(replaced, allocate * sizeof(unsigned char));
            if (!tmp_ptr) {
                flb_error("[in_regexp] could not allocate memory");
                flb_free(replaced);
            }
            replaced = tmp_ptr;
        }
        memcpy((unsigned char *)replaced + len, (unsigned char *)val,
               (vlen - offset) * sizeof(unsigned char));
        len += vlen - offset;
        offset = 0;
    }

    onig_region_free(region, 1 /* 1:free self, 0:free contents only */);
    *out_size = len;
    *out_buf = replaced;
    return FLB_FILTER_MODIFIED;
}

/* Given a msgpack record, match based on the defined rule */
static inline int regexp_match_data(struct regexp_rule *rule, char *val,
                                    size_t vlen) {
    unsigned char *start, *range, *end;
    ssize_t ret;
    OnigRegion *region = onig_region_new();

    unsigned long offset = 0;

    end = (unsigned char *)val + (vlen - offset);
    range = end;
    start = (unsigned char *)val;
    ret = onig_search(rule->regex->regex, (unsigned char *)val, end, start,
                      range, region, ONIG_OPTION_NONE);
    /* we have got a match */
    if (ret >= 0) {
        // we have got a match
        ret = REGEXP_SKIP;
    } else if (ret == ONIG_MISMATCH) {
        ret = FLB_FILTER_NOTOUCH;
    } else { /* error */
        OnigUChar s[ONIG_MAX_ERROR_MESSAGE_LEN];
        onig_error_code_to_str(s, ret);
        fprintf(stderr, "ERROR: %s\n", s);
        return -1;
    }

    onig_region_free(region, 1 /* 1:free self, 0:free contents only */);
    return ret;
}

static inline int apply_mutations(void *context, char *val, size_t vlen,
                                  unsigned char **out_buf, size_t *out_size) {
    struct mk_list *head;
    struct regexp_rule *rule;
    struct regexp_ctx *ctx = context;
    unsigned char *buf, *tmp_ptr;
    size_t buf_size;

    unsigned char *tmp_buf;
    size_t tmp_size;

    buf = val;
    buf_size = vlen;

    int ret;

    /* Lookup parser */
    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct regexp_rule, _head);

        switch (rule->type) {
            case REGEXP_SKIP: {
                ret = regexp_match_data(rule, buf, buf_size);
                if (ret == REGEXP_SKIP) {
                    return ret;
                }
                break;
            }
            case REGEXP_SUBST: {
                ret = regexp_replace_data(
                    rule, buf, buf_size, (unsigned char **)&tmp_buf, &tmp_size);
                if (buf != val) {
                    flb_free(buf);
                }
                buf = tmp_buf;
                buf_size = tmp_size;
                break;
            }
        }
    }

    *out_buf = tmp_buf;
    *out_size = tmp_size;

    return FLB_FILTER_MODIFIED;
}

static int cb_regexp_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config, void *data) {
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

static int msgpack_handler(msgpack_packer *pk, void *context,
                           msgpack_object d) {
    int ret = FLB_FALSE;
    struct regexp_ctx *ctx = context;

    switch (d.type) {
        case MSGPACK_OBJECT_NIL:
            msgpack_pack_nil(pk);
            break;

        case MSGPACK_OBJECT_BOOLEAN:
            if (d.via.boolean) {
                return msgpack_pack_true(pk);
            } else {
                return msgpack_pack_false(pk);
            }
            break;

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            msgpack_pack_uint64(pk, d.via.u64);
            break;

        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            msgpack_pack_int64(pk, d.via.i64);
            break;

        case MSGPACK_OBJECT_FLOAT32:
            msgpack_pack_float(pk, (float)d.via.f64);
            break;

        case MSGPACK_OBJECT_FLOAT64:
            msgpack_pack_double(pk, d.via.f64);
            break;

        case MSGPACK_OBJECT_STR: {
            unsigned char *str_buf;
            size_t str_size;

            int ret = apply_mutations(ctx, d.via.str.ptr, d.via.str.size,
                                      (unsigned char **)&str_buf, &str_size);

            if (ret == REGEXP_SKIP) {
                ret = msgpack_pack_str(pk, d.via.str.size);
                if (ret < 0) {
                    return ret;
                }
                msgpack_pack_str_body(pk, d.via.str.ptr, d.via.str.size);
                return REGEXP_SKIP;
            } else {
                ret = msgpack_pack_str(pk, str_size);
                if (ret < 0) {
                    return ret;
                }
                msgpack_pack_str_body(pk, str_buf, str_size);
                free(str_buf);
            }
        } break;

        case MSGPACK_OBJECT_BIN: {
            unsigned char *bin_buf;
            size_t bin_size;

            int ret = apply_mutations(ctx, d.via.bin.ptr, d.via.bin.size,
                                      (unsigned char **)&bin_buf, &bin_size);

            if (ret == REGEXP_SKIP) {
                ret = msgpack_pack_bin(pk, d.via.bin.size);
                if (ret < 0) {
                    return ret;
                }
                msgpack_pack_bin_body(pk, d.via.bin.ptr, d.via.bin.size);
                return REGEXP_SKIP;
            } else {
                ret = msgpack_pack_bin(pk, bin_size);
                if (ret < 0) {
                    return ret;
                }
                msgpack_pack_bin_body(pk, bin_buf, bin_size);
                free(bin_buf);
            }

        } break;

        case MSGPACK_OBJECT_EXT: {
            ret = msgpack_pack_ext(pk, d.via.ext.size, d.via.ext.type);
            if (ret < 0) {
                return ret;
            }
            msgpack_pack_ext_body(pk, d.via.ext.ptr, d.via.ext.size);
            break;
        }

        case MSGPACK_OBJECT_ARRAY:
            msgpack_pack_array(pk, d.via.array.size);
            msgpack_object *o = d.via.array.ptr;
            msgpack_object *const oend = d.via.array.ptr + d.via.array.size;
            for (; o != oend; ++o) {
                ret = msgpack_handler(pk, ctx, *o);
                if (ret == REGEXP_SKIP) {
                    return REGEXP_SKIP;
                }
            }
            break;

        case MSGPACK_OBJECT_MAP:
            msgpack_pack_map(pk, d.via.map.size);
            msgpack_object_kv *kv = d.via.map.ptr;
            msgpack_object_kv *const kvend = d.via.map.ptr + d.via.map.size;
            for (; kv != kvend; ++kv) {
                ret = msgpack_handler(pk, ctx, kv->key);
                if (ret == REGEXP_SKIP) {
                    return REGEXP_SKIP;
                }
                ret = msgpack_handler(pk, ctx, kv->val);
                if (ret == REGEXP_SKIP) {
                    return REGEXP_SKIP;
                }
            }
            break;

        default:
            flb_warn("[%s] unknown msgpack type %i", __FUNCTION__, d.type);
    }

    return ret;
}

static int cb_regexp_filter(void *data, size_t bytes, char *tag, int tag_len,
                            void **ret_buf, size_t *ret_size,
                            struct flb_filter_instance *f_ins, void *context,
                            struct flb_config *config) {
    int ret = FLB_FILTER_MODIFIED;
    msgpack_unpacked result;
    size_t off = 0;
    (void)f_ins;
    (void)config;

    msgpack_sbuffer tmp_sbuf, sbuf;
    msgpack_packer tmp_pck, pck;
    struct mk_list *head;

    struct regexp_ctx *ctx = context;
    struct regexp_rule *rule;

    /* Create out msgpack buffer */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
        if (msgpack_handler(&tmp_pck, ctx, result.data) == REGEXP_SKIP) {
            struct msgpack_object obj = result.data;
            msgpack_pack_object(&pck, obj);
        } else {
            msgpack_sbuffer_write(&sbuf, tmp_sbuf.data, tmp_sbuf.size);
        }
    }

    /* link new buffers */
    *ret_buf = sbuf.data;
    *ret_size = sbuf.size;
    return ret;
}

static int cb_regexp_exit(void *data, struct flb_config *config) {
    struct regexp_ctx *ctx = data;

    delete_rules(ctx);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_regexp_plugin = {
    .name = "regexp",
    .description = "regexp events by specified field values",
    .cb_init = cb_regexp_init,
    .cb_filter = cb_regexp_filter,
    .cb_exit = cb_regexp_exit,
    .flags = 0};
