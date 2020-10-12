#include <stdlib.h>

#include "include/kpatch_log.h"
#include "include/kpatch_parse.h"
#include "include/kpatch_flags.h"

/* break manually crafted multiple statements separated by ; to separate lines */
void init_multilines(struct kp_file *f)
{
	int i, nr, sz = 64, slen, first_token;
	char **lines = NULL, *s, *se;
	int *lines_num = NULL;
	kpstr_t t;

	nr = 0;
	for (i = 0; i < f->nr_lines; i++) {
		if (nr + 1000 >= sz || !lines) {
			sz *= 2;
			lines = kp_realloc(lines, (sz/2) * sizeof(char *), sz * sizeof(char *));
			lines_num = kp_realloc(lines_num, (sz/2) * sizeof(int), sz * sizeof(int));
		}

		s = f->lines[i];
		if (strpbrk(s, ";:") != NULL) {
			while (s && *s) {
				se = s;
				slen = strlen(s);
				first_token = 1;
				while (se) {
					get_token(&se, &t);
					if (t.l == 1 && t.s[0] == '#')
						goto done;
					if (t.l == 2 && t.s[0] == '/' && t.s[1] == '/')
						goto done;
					if (t.l == 1 && t.s[0] == ';') {
						slen = t.s - s;
						break;
					}
					/* first token with ':' after is
					 * the label, separate it unless
					 * it is done already (next non-blank
					 * is '\0')
					 */
					if (first_token && se &&
					    se[0] == ':' &&
					    se[1] != '\0') {
						slen = se - s + 1;
						se++;
						break;
					}
					first_token = 0;
				}
				lines[nr] = strndup(s, slen);
				s = se;
				lines_num[nr] = i;
				nr++;
				if (nr >= sz)
					kpfatal("oops, not prepared to handle >1000 asm statements in single line");
			}
			free(f->lines[i]);
		} else {
done:
			lines[nr] = s;
			lines_num[nr] = i;
			nr++;
		}
	}
	free(f->lines);
	f->lines = lines;
	f->lines_num = lines_num;
	f->nr_lines = nr;
}

int parse_ctype(char *origs, bool with_checks)
{
	char *s = origs;
	int type;
	kpstr_t t;

	s = skip_blanks(s);
	if (s[0] == '#')
		return DIRECTIVE_COMMENT;		/* Single-line comment */

	if (s[0] == '/' && s[1] == '/')
		return DIRECTIVE_COMMENT;      /* Arm disassembly support c style comment */

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
