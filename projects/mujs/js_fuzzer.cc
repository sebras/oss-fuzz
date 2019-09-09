/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <cstdint>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <mujs.h>

static const char *require_js =
        "function require(name) {\n"
        "var cache = require.cache;\n"
        "if (name in cache) return cache[name];\n"
        "var exports = {};\n"
        "cache[name] = exports;\n"
        "Function('exports', read(name+'.js'))(exports);\n"
        "return exports;\n"
        "}\n"
        "require.cache = Object.create(null);\n"
;

static const char *stacktrace_js =
        "Error.prototype.toString = function() {\n"
        "if (this.stackTrace) return this.name + ': ' + this.message + this.stackTrace;\n"
        "return this.name + ': ' + this.message;\n"
        "};\n"
;

#define ALIGNMENT 16
#define MAX_ALLOCATION (1024 * 1024 * 1024)

static uint64_t total = 0;

static void *js_realloc_ossufzz(void *memctx, void *ptr, int size)
{
	unsigned char *oldptr = ptr ? (unsigned char *) ptr - ALIGNMENT : NULL;

	if (size > SIZE_MAX - ALIGNMENT)
		return NULL;

	if (size > MAX_ALLOCATION - ALIGNMENT - total)
		return NULL;

	if (oldptr == NULL)
	{
		if (size == 0)
			return NULL;

		ptr = malloc(size + ALIGNMENT);
	}
	else
	{
		int oldsize;
		memcpy(&oldsize, oldptr, sizeof(oldsize));

		if (size == 0)
		{
			total -= oldsize + ALIGNMENT;
			free(oldptr);
			return NULL;
		}

		ptr = realloc(oldptr, size + ALIGNMENT);
		if (ptr == NULL)
			return NULL;

		total -= oldsize + ALIGNMENT;
	}

	memcpy(ptr, &size, sizeof(size));
	total += size + ALIGNMENT;
	return (unsigned char *) ptr + ALIGNMENT;
}

static void jsB_gc(js_State *J)
{
	int report = js_toboolean(J, 1);
	js_gc(J, report);
	js_pushundefined(J);
}

static void jsB_compile(js_State *J)
{
	const char *source = js_tostring(J, 1);
	const char *filename = js_isdefined(J, 2) ? js_tostring(J, 2) : "[string]";
	js_loadstring(J, filename, source);
}

static void jsB_repr(js_State *J)
{
	js_repr(J, 1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *str;
  js_State *J;

  str = (char *) malloc(size + 1);
  memcpy(str, data, size);
  str[size] = '\0';

  J = js_newstate(js_realloc_ossufzz, NULL, 0);

  js_newcfunction(J, jsB_gc, "gc", 0);
  js_setglobal(J, "gc");

  js_newcfunction(J, jsB_compile, "compile", 2);
  js_setglobal(J, "compile");

  js_newcfunction(J, jsB_repr, "repr", 0);
  js_setglobal(J, "repr");

  js_dostring(J, require_js);
  js_dostring(J, stacktrace_js);
  js_dostring(J, str);
  js_gc(J, 0);
  js_freestate(J);

  free(str);

  return 0;
}
