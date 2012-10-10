/*
 * Copyright (c) 2010 Richard Braun.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LIB_ASSERT_H
#define _LIB_ASSERT_H

#ifdef NDEBUG
#define assert(expression) ((void)(expression))
#else /* NDEBUG */

#include <kern/panic.h>
#include <lib/macros.h>

/*
 * Panic if the given expression is false.
 */
#define assert(expression)                                          \
MACRO_BEGIN                                                         \
    if (unlikely(!(expression)))                                    \
        panic("assertion (%s) failed in %s:%d, function %s()",      \
              __QUOTE(expression), __FILE__, __LINE__, __func__);   \
MACRO_END

#endif /* NDEBUG */

#endif /* _LIB_ASSERT_H */