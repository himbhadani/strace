/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 1999-2018 The strace developers.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "defs.h"
#include "xstring.h"
#include <stdarg.h>

const char *
xlookup(const struct xlat *xlat, const uint64_t val)
{
	for (; xlat->str != NULL; xlat++)
		if (xlat->val == val)
			return xlat->str;
	return NULL;
}

static int
xlat_bsearch_compare(const void *a, const void *b)
{
	const uint64_t val1 = *(const uint64_t *) a;
	const uint64_t val2 = ((const struct xlat *) b)->val;
	return (val1 > val2) ? 1 : (val1 < val2) ? -1 : 0;
}

const char *
xlat_search(const struct xlat *xlat, const size_t nmemb, const uint64_t val)
{
	const struct xlat *e =
		bsearch((const void *) &val,
			xlat, nmemb, sizeof(*xlat), xlat_bsearch_compare);

	return e ? e->str : NULL;
}

/**
 * Print entry in struct xlat table, if there.
 *
 * @param val   Value to search a literal representation for.
 * @param dflt  String (abbreviated in comment syntax) which should be emitted
 *              if no appropriate xlat value has been found.
 * @param style Style in which xlat value should be printed.
 * @param xlat  (And the following arguments) Pointers to arrays of xlat values.
 *              The last argument should be NULL.
 * @return      1 if appropriate xlat value has been found, 0 otherwise.
 */
int
printxvals_ex(const uint64_t val, const char *dflt, enum xlat_style style,
	      const struct xlat *xlat, ...)
{
	if (style == XLAT_STYLE_RAW) {
		tprintf("%#" PRIx64, val);
		return 0;
	}

	va_list args;

	va_start(args, xlat);
	for (; xlat; xlat = va_arg(args, const struct xlat *)) {
		const char *str = xlookup(xlat, val);

		if (str) {
			if (style == XLAT_STYLE_VERBOSE) {
				tprintf("%#" PRIx64, val);
				tprints_comment(str);
			} else {
				tprints(str);
			}

			va_end(args);
			return 1;
		}
	}
	/* No hits -- print raw # instead. */
	tprintf("%#" PRIx64, val);
	tprints_comment(dflt);

	va_end(args);

	return 0;
}

int
sprintxval_ex(char *const buf, const size_t size, const struct xlat *const x,
	      const unsigned int val, const char *const dflt,
	      enum xlat_style style)
{
	if (style == XLAT_STYLE_RAW)
		return xsnprintf(buf, size, "%#x", val);

	const char *const str = xlookup(x, val);

	if (str) {
		if (style == XLAT_STYLE_VERBOSE)
			return xsnprintf(buf, size, "%#x /* %s */", val, str);
		else
			return xsnprintf(buf, size, "%s", str);
	}
	if (dflt)
		return xsnprintf(buf, size, "%#x /* %s */", val, dflt);

	return xsnprintf(buf, size, "%#x", val);
}

/**
 * Print entry in sorted struct xlat table, if it is there.
 *
 * @param xlat      Pointer to an array of xlat values (not terminated with
 *                  XLAT_END).
 * @param xlat_size Number of xlat elements present in array (usually ARRAY_SIZE
 *                  if array is declared in the unit's scope and not
 *                  terminated with XLAT_END).
 * @param val       Value to search literal representation for.
 * @param dflt      String (abbreviated in comment syntax) which should be
 *                  emitted if no appropriate xlat value has been found.
 * @param style     Style in which xlat value should be printed.
 * @return          1 if appropriate xlat value has been found, 0
 *                  otherwise.
 */
int
printxval_searchn_ex(const struct xlat *xlat, size_t xlat_size, uint64_t val,
		     const char *dflt, enum xlat_style style)
{
	if (style == XLAT_STYLE_RAW) {
		tprintf("%#" PRIx64, val);
		return 0;
	}

	const char *s = xlat_search(xlat, xlat_size, val);

	if (s) {
		if (style == XLAT_STYLE_VERBOSE) {
			tprintf("%#" PRIx64, val);
			tprints_comment(s);
		} else {
			tprints(s);
		}
		return 1;
	}

	tprintf("%#" PRIx64, val);
	tprints_comment(dflt);

	return 0;
}

/*
 * Interpret `xlat' as an array of flags
 * print the entries whose bits are on in `flags'
 */
void
addflags(const struct xlat *xlat, uint64_t flags)
{
	for (; xlat->str; xlat++) {
		if (xlat->val && (flags & xlat->val) == xlat->val) {
			tprintf("|%s", xlat->str);
			flags &= ~xlat->val;
		}
	}
	if (flags) {
		tprintf("|%#" PRIx64, flags);
	}
}

/*
 * Interpret `xlat' as an array of flags.
 * Print to static string the entries whose bits are on in `flags'
 * Return static string.  If 0 is provided as flags, and there is no flag that
 * has the value of 0 (it should be the first in xlat table), return NULL.
 *
 * Expected output:
 * +------------+------------+---------+------------+
 * | flags != 0 | xlat found | style   | output     |
 * +------------+------------+---------+------------+
 * | false      | (any)      | raw     | <none>     |
 * | true       | (any)      | raw     | VAL        |
 * +------------+------------+---------+------------+
 * | false      | false      | abbrev  | <none>     |
 * | true       | false      | abbrev  | VAL        |
 * | (any)      | true       | abbrev  | XLAT       |
 * +------------+------------+---------+------------+
 * | false      | false      | verbose | <none>     |
 * | true       | false      | verbose | VAL        |
 * | (any)      | true       | verbose | VAL (XLAT) |
 * +------------+------------+---------+------------+
 */
const char *
sprintflags_ex(const char *prefix, const struct xlat *xlat, uint64_t flags,
	       enum xlat_style style)
{
	static char outstr[1024];
	char *outptr;
	int found = 0;

	outptr = stpcpy(outstr, prefix);

	if (style == XLAT_STYLE_RAW) {
		if (!flags)
			return NULL;

		outptr = xappendstr(outstr, outptr, "%#" PRIx64, flags);

		return outstr;
	}

	if (flags == 0 && xlat->val == 0 && xlat->str) {
		if (style == XLAT_STYLE_VERBOSE) {
			outptr = xappendstr(outstr, outptr, "0 /* %s */",
					    xlat->str);
		} else {
			strcpy(outptr, xlat->str);
		}

		return outstr;
	}

	if (style == XLAT_STYLE_VERBOSE && flags)
		outptr = xappendstr(outstr, outptr, "%#" PRIx64, flags);

	for (; flags && xlat->str; xlat++) {
		if (xlat->val && (flags & xlat->val) == xlat->val) {
			if (found)
				*outptr++ = '|';
			else if (style == XLAT_STYLE_VERBOSE)
				outptr = stpcpy(outptr, " /* ");

			outptr = stpcpy(outptr, xlat->str);
			found = 1;
			flags &= ~xlat->val;
		}
	}

	if (flags) {
		if (found)
			*outptr++ = '|';
		if (found || style != XLAT_STYLE_VERBOSE)
			outptr = xappendstr(outstr, outptr, "%#" PRIx64, flags);
	} else {
		if (!found)
			return NULL;
	}

	if (found && style == XLAT_STYLE_VERBOSE)
		outptr = stpcpy(outptr, " */");

	return outstr;
}

/**
 * Print flags from multiple xlat tables.
 *
 * Expected output:
 * +------------+--------------+------------+---------+------------+
 * | flags != 0 | dflt != NULL | xlat found | style   | output     |
 * +------------+--------------+------------+---------+------------+
 * | false      | false        | (any)      | raw     | <none>     |
 * | false      | true         | (any)      | raw     | VAL        |
 * | true       | (any)        | (any)      | raw     | VAL        |
 * +------------+--------------+------------+---------+------------+
 * | false      | false        | false      | abbrev  | <none>     |
 * | false      | true         | false      | abbrev  | VAL        |
 * | true       | false        | false      | abbrev  | VAL        |
 * | true       | true         | false      | abbrev  | VAL (DFLT) |
 * | (any)      | (any)        | true       | abbrev  | XLAT       |
 * +------------+--------------+------------+---------+------------+
 * | false      | false        | false      | verbose | <none>     |
 * | false      | true         | false      | verbose | VAL        |
 * | true       | false        | false      | verbose | VAL        |
 * | true       | true         | false      | verbose | VAL (DFLT) |
 * | (any)      | (any)        | true       | verbose | VAL (XLAT) |
 * +------------+--------------+------------+---------+------------+
 */
int
printflags_ex(uint64_t flags, const char *dflt, enum xlat_style style,
	      const struct xlat *xlat, ...)
{
	if (style == XLAT_STYLE_RAW) {
		if (flags || dflt) {
			tprintf("%#" PRIx64, flags);
			return 1;
		}

		return 0;
	}

	const char *init_sep = "";
	unsigned int n = 0;
	va_list args;

	if (style == XLAT_STYLE_VERBOSE) {
		init_sep = " /* ";
		if (flags)
			tprintf("%#" PRIx64, flags);
	}

	va_start(args, xlat);
	for (; xlat; xlat = va_arg(args, const struct xlat *)) {
		for (; (flags || !n) && xlat->str; ++xlat) {
			if ((flags == xlat->val) ||
			    (xlat->val && (flags & xlat->val) == xlat->val)) {
				if (style == XLAT_STYLE_VERBOSE && !flags)
					tprints("0");
				tprintf("%s%s",
					(n++ ? "|" : init_sep), xlat->str);
				flags &= ~xlat->val;
			}
			if (!flags)
				break;
		}
	}
	va_end(args);

	if (n) {
		if (flags) {
			tprintf("|%#" PRIx64, flags);
			n++;
		}

		if (style == XLAT_STYLE_VERBOSE)
			tprints(" */");
	} else {
		if (flags) {
			if (style != XLAT_STYLE_VERBOSE)
				tprintf("%#" PRIx64, flags);
			tprints_comment(dflt);
		} else {
			if (dflt)
				tprints("0");
		}
	}

	return n;
}
