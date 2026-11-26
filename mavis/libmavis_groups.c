/*
 * libmavis_groups.c
 * (C)2011-2022 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "groups"

#include "misc/sysconf.h"
#include <stdio.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include "misc/strops.h"
#include "misc/io.h"
#include "groups.h"
#include "misc/memops.h"
#include "debug.h"
#include "log.h"

#ifdef WITH_PCRE2
#include "misc/mypcre2.h"
#endif

#include <regex.h>

static const char rcsid[] __attribute__((used)) = "$Id$";


struct regex_list;

#define MAVIS_CTX_PRIVATE	int resolve_gid; \
				int resolve_gids; \
				int resolve_gid_attr; \
				int resolve_gids_attr; \
				struct regex_list *group_regex; \
				struct regex_list *groups_regex; \
				struct regex_list *memberof_regex; \
				struct gid_list *gid; \
				struct gid_list *gids;

#include "mavis.h"

struct regex_list {
    struct regex_list *next;
    int negate;
    enum token type;
    void *p;
};

struct gid_list {
    struct gid_list *next;
    int negate;
    gid_t gid_start;
    gid_t gid_end;
};

static void parse_filter_regex(struct sym *sym, struct regex_list **l)
{
    int negate = 0;

    if (sym->code == S_not) {
	negate = 1;
	sym_get(sym);
    }

    do {
	int errcode = 0;
	while (*l)
	    l = &(*l)->next;
	*l = Xcalloc(1, sizeof(struct regex_list));
	(*l)->negate = negate;
	if (sym->code == S_slash) {
#ifdef WITH_PCRE2
	    PCRE2_SIZE erroffset;
	    (*l)->type = S_slash;
	    (*l)->p = (void *)
		mypcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | common_data.regex_pcre_flags, &errcode, &erroffset, NULL);
	    if (!(*l)->p) {
		PCRE2_UCHAR buffer[256];
		pcre2_get_error_message(errcode, buffer, sizeof(buffer));
		parse_error(sym, "In PCRE2 expression /%s/ at offset %zu: %s", sym->buf, erroffset, buffer);
	    }
#else
	    parse_error(sym, "You're using PCRE2 syntax, but this binary wasn't compiled with PCRE2 support.");
#endif
	} else {
	    (*l)->type = S_regex;
	    (*l)->p = Xcalloc(1, sizeof(regex_t));
	    errcode = regcomp((regex_t *) (*l)->p, sym->buf, REG_EXTENDED | REG_NOSUB | REG_NEWLINE | common_data.regex_posix_flags);
	    if (errcode) {
		char e[160];
		regerror(errcode, (regex_t *) (*l)->p, e, sizeof(e));
		parse_error(sym, "In regular expression '%s': %s", sym->buf, e);
	    }
	}
	sym_get(sym);
    } while (parse_comma(sym));
}

static void parse_gid(struct sym *sym, struct gid_list **l)
{
    int negate = 0;
    if (sym->code == S_not) {
	negate = 1;
	sym_get(sym);
    }

    do {
	u_int gs, ge;
	while (*l)
	    l = &(*l)->next;
	*l = Xcalloc(1, sizeof(struct gid_list));
	(*l)->negate = negate;

	switch (sscanf(sym->buf, "%u-%u", &gs, &ge)) {
	case 1:
	    ge = gs;
	case 2:
	    break;
	default:
	    parse_error(sym, "Expected numeric GID or GID range, but got \"%s\"", sym->buf);
	}
	(*l)->gid_start = gs;
	(*l)->gid_end = ge;
	sym_get(sym);
    } while (parse_comma(sym));
}

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    mcx->resolve_gid_attr = AV_A_GID;
    mcx->resolve_gids_attr = AV_A_GIDS;

    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, NULL, sym);
	    continue;
	case S_resolve:
	    // resolve gid = (yes|no)
	    // resolve gid attribute = <attr>
	    sym_get(sym);
	    switch (sym->code) {
	    case S_gid:
		sym_get(sym);
		switch (sym->code) {
		case S_attr:
		    sym_get(sym);
		    parse(sym, S_equal);
		    mcx->resolve_gid_attr = av_attribute_to_i(sym->buf);
		    if (mcx->resolve_gid_attr < 0)
			parse_error(sym, "'%s' is not a recognized attribute", sym->buf);
		    sym_get(sym);
		    continue;
		case S_equal:
		    parse(sym, S_equal);
		    mcx->resolve_gid = parse_bool(sym);
		    continue;
		default:
		    parse_error_expect(sym, S_attr, S_equal, S_unknown);
		}
	    case S_gids:
		// resolve gids = (yes|no)
		// resolve gids attribute = <attr>
		sym_get(sym);
		switch (sym->code) {
		case S_attr:
		    sym_get(sym);
		    parse(sym, S_equal);
		    mcx->resolve_gids_attr = av_attribute_to_i(sym->buf);
		    if (mcx->resolve_gids_attr < 0)
			parse_error(sym, "'%s' is not a recognized attribute", sym->buf);
		    sym_get(sym);
		    continue;
		case S_equal:
		    parse(sym, S_equal);
		    mcx->resolve_gids = parse_bool(sym);
		    continue;
		default:
		    parse_error_expect(sym, S_attr, S_equal, S_unknown);
		}
	    default:
		parse_error_expect(sym, S_gid, S_gids, S_unknown);
	    }
	case S_group:
	    sym_get(sym);
	    parse(sym, S_filter);
	    sym->flag_parse_pcre = 1;
	    parse(sym, S_equal);
	    // group filter = [not] regex ...
	    parse_filter_regex(sym, &mcx->group_regex);
	    sym->flag_parse_pcre = 0;
	    continue;
	case S_groups:
	    sym_get(sym);
	    parse(sym, S_filter);
	    sym->flag_parse_pcre = 1;
	    parse(sym, S_equal);
	    // groups filter = [not] regex ...
	    parse_filter_regex(sym, &mcx->groups_regex);
	    sym->flag_parse_pcre = 0;
	    continue;
	case S_memberof:
	    sym_get(sym);
	    parse(sym, S_filter);
	    sym->flag_parse_pcre = 1;
	    parse(sym, S_equal);
	    // memberof filter = [not] regex ...
	    parse_filter_regex(sym, &mcx->memberof_regex);
	    sym->flag_parse_pcre = 0;
	    continue;
	case S_gid:
	    sym_get(sym);
	    parse(sym, S_filter);
	    parse(sym, S_equal);
	    // gid filter = [not] <gid>[-<gid>][,<gid>[-<gid>]]+
	    parse_gid(sym, &mcx->gid);
	    continue;
	case S_gids:
	    sym_get(sym);
	    parse(sym, S_filter);
	    parse(sym, S_equal);
	    // gids filter = [not] <gid>[-<gid>][,<gid>[-<gid>]]+
	    parse_gid(sym, &mcx->gids);
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_resolve, S_script, S_group, S_groups, S_memberof, S_gid, S_gids, S_action, S_unknown);
	}
    }
}

static int good_gid(struct gid_list *l, u_long gid)
{
    if (!l)
	return -1;
    while (l) {
	int match = l->gid_start <= (gid_t) gid && l->gid_end >= (gid_t) gid;
	if (l->negate)
	    match = !match;
	if (match)
	    return match;
	l = l->next;
    }
    return 0;
}

static int rxmatch(void *v, char *s, enum token token)
{
#ifdef WITH_PCRE2
    int pcre_res = 0;
    pcre2_match_data *match_data = NULL;
#endif
    switch (token) {
    case S_slash:
#ifdef WITH_PCRE2
	match_data = pcre2_match_data_create_from_pattern((pcre2_code *) v, NULL);
	pcre_res = mypcre2_match((pcre2_code *) v, (PCRE2_SPTR8) s, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
	if (pcre_res < 0 && pcre_res != PCRE2_ERROR_NOMATCH) {
	    report_cfg_error(LOG_INFO, ~0, "PCRE2 matching error: %d", pcre_res);
	}
	pcre2_match_data_free(match_data);
	return -1 < pcre_res;
#endif
    default:
	return !regexec((regex_t *) v, s, 0, NULL, 0);
    }
}

static int good_name(struct regex_list *l, char *s)
{
    if (!l)
	return -1;
    while (l) {
	int match = rxmatch(l->p, s, l->type);

	if (l->negate)
	    match = !match;
	if (match)
	    return match;
	l = l->next;
    }
    return 0;
}

// 1 if a plain value of the list in attr can carry name (MEMBEROF needs quoted values)
static int plain_value(int attr, char *name)
{
    size_t len = strlen(name);
    return attr != AV_A_MEMBEROF && len && !strpbrk(name, ",\r\n") && !strchr("\"' \t", *name) && !strchr(" \t", name[len - 1]);
}

// A group name into the list l of attr. For a list attribute: quoted, or plain if it cannot be quoted (a backslash
// at the end) and a plain value can carry it. A resolved name with a backslash is plain if the tac_plus parser reads
// it as one word: that parser reads C escapes in quotes. -1: the list cannot carry it
static int add_group_name(struct av_list *l, int attr, char *name, int resolved)
{
    size_t len = strlen(name);
    if (!av_list_attribute(attr)
	|| (resolved && strchr(name, '\\') && plain_value(attr, name) && *name != '#' && !strpbrk(name, " \t={}()[]|&!")))
	av_list_add(l, name, len);
    else if (av_list_add_quoted(l, name, len)) {
	if (!plain_value(attr, name))
	    return -1;
	av_list_add(l, name, len);
    }
    return 0;
}

// A resolved group name that the list cannot carry: the answer fails
static int group_name_refused(av_ctx *ac, int attr, struct av_list *l)
{
    logmsg("%s: a group name of user %s does not fit into %s", MAVIS_name, av_get(ac, AV_A_USER), av_char[attr].name);
    free(l->buf);
    av_list_set_malformed(ac, attr, MAVIS_name);
    return MAVIS_FINAL;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    char *s = NULL;
    // each list is built in one buffer: appending to the attribute would copy the whole list for each value
    struct av_list l = { 0 };

    // the filter cannot say which values of a malformed list pass: the answer fails
    int a = av_lists_check(*ac);
    if (a > -1) {
	av_list_refuse(*ac, a, MAVIS_name);
	return MAVIS_FINAL;
    }
    if (mcx->resolve_gid) {
	s = av_get(*ac, AV_A_GID);

	if (s) {
	    u_long u = strtoul(s, NULL, 10);
	    if (u || errno != EINVAL) {
		struct group *g;
		if (!good_gid(mcx->gid, u)) {
		    av_unset(*ac, AV_A_GID);
		} else {
		    g = getgrgid((gid_t) u);
		    if (g && good_name(mcx->group_regex, g->gr_name) && add_group_name(&l, mcx->resolve_gid_attr, g->gr_name, 1))
			return group_name_refused(*ac, mcx->resolve_gid_attr, &l);
		    av_list_set(*ac, mcx->resolve_gid_attr, &l);
		}
	    } else
		av_unset(*ac, mcx->resolve_gid_attr);
	}
    }

    if (mcx->resolve_gids) {
	s = av_get(*ac, AV_A_GIDS);
	if (s) {
	    char *gids = Xstrdup(s);
	    for (char *t = gids; *t;)
		if (isdigit((int) *t)) {
		    u_long u = strtoul(t, &t, 10);
		    if (u || errno != EINVAL) {
			struct group *g;
			if (!good_gid(mcx->gids, u))
			    continue;
			g = getgrgid((gid_t) u);
			if (g && good_name(mcx->groups_regex, g->gr_name) && add_group_name(&l, mcx->resolve_gids_attr, g->gr_name, 1)) {
			    free(gids);
			    return group_name_refused(*ac, mcx->resolve_gids_attr, &l);
			}
		    }
		} else
		    t++;
	    free(gids);
	    av_list_set(*ac, mcx->resolve_gids_attr, &l);
	}
    }

    // the lists are well-formed here: a quoted value goes out quoted (a decoded one can always be quoted again), a
    // plain one plain
    s = av_get(*ac, AV_A_TACMEMBER);
    if (s) {
	char *list = Xstrdup(s), *rest = list, *v;
	int quoted;
	while (av_list_next(&rest, &v, &quoted) > 0)
	    if (good_name(mcx->groups_regex, v)) {
		if (quoted)
		    add_group_name(&l, AV_A_TACMEMBER, v, 0);
		else
		    av_list_add(&l, v, strlen(v));
	    }
	free(list);
	av_list_set(*ac, AV_A_TACMEMBER, &l);
    }

    s = av_get(*ac, AV_A_MEMBEROF);
    if (s) {
	char *list = Xstrdup(s), *rest = list, *v;
	while (av_list_next(&rest, &v, NULL) > 0)
	    if (good_name(mcx->memberof_regex, v))
		add_group_name(&l, AV_A_MEMBEROF, v, 0);
	free(list);
	av_list_set(*ac, AV_A_MEMBEROF, &l);
    }

    return MAVIS_FINAL;
}

static void drop_gr(struct regex_list *r)
{
    while (r) {
	struct regex_list *l = r->next;
#ifdef WITH_PCRE2
	if (r->type == S_slash)
	    pcre2_code_free(r->p);
	else
#endif
	    regfree(r->p);

	free(r);
	r = l;
    }
}

static void drop_gl(struct gid_list *r)
{
    while (r) {
	struct gid_list *l = r->next;
	free(r);
	r = l;
    }
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    drop_gr(mcx->group_regex);
    drop_gr(mcx->groups_regex);
    drop_gl(mcx->gid);
    drop_gl(mcx->gids);
}

#include "mavis_glue.c"
