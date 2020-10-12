#include <stdlib.h>

#include "include/kpatch_log.h"
#include "include/kpatch_parse.h"
#include "include/kpatch_flags.h"

int parse_ctype(char *origs, bool with_checks)
{
	char *s = origs;
	int type;
	kpstr_t t;

	s = skip_blanks(s);
	if (s[0] == '#')
		return DIRECTIVE_COMMENT;		/* Single-line comment */

	get_token(&s, &t);
	type = find_ctype(&t);

	if (type >= 0)
		return type;

	/*
	 * Asm labels starting from digits are local labels, they can be even created multiple times in the same function.
	 * So there is no reason to handle them and bother with renaming at all. It would create conflicts at our brains
	 * and require special tracking and matching... Brrrr.... */
	if (s && *s == ':')
		return !isdigit(t.s[0]) ? DIRECTIVE_LABEL : DIRECTIVE_LOCAL_LABEL;

	return DIRECTIVE_OTHER;
}
