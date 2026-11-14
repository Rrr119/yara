/*
Copyright (c) 2026. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#if !defined(_WIN32) && !defined(__CYGWIN__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <yara.h>

#include "args.h"
#include "common.h"
#include "unicode.h"

#define MAX_ARGS_EXT_VAR 32
#define MAX_RULE_TAGS     64

#define STATUS_OK            "ok"
#define STATUS_TIMEOUT       "timeout"
#define STATUS_MEMORY_LIMIT  "memory_limit"
#define STATUS_ERROR         "error"

typedef struct
{
  char** items;
  size_t count;
  size_t capacity;
} PATH_LIST;

typedef struct
{
  uint64_t match_time_ns;
  uint64_t condition_time_ns;
  uint64_t total_time_ns;
  uint64_t atom_matches;
  uint64_t match_samples;
  uint64_t matched_samples;
} RULE_STATS;

typedef struct
{
  uint64_t hit_count;
  uint64_t atom_matches;
  uint64_t match_samples;
  uint64_t match_time_ns;
} STRING_STATS;

typedef struct
{
  YR_RULE* rule;
  const char* identifier;
  const char* ns;
  char** tags;
  size_t tag_count;
  char* author;
  char* severity;
} RULE_META;

typedef struct
{
  char* path;
  uint64_t size;
  uint64_t elapsed_ns;
  const char* status;
  int error_code;
  uint32_t matched_count;
  uint32_t* matched_rules;
} SAMPLE_STATS;

typedef struct
{
  char* key;
  uint64_t rule_count;
  uint64_t matched_samples;
  uint64_t total_time_ns;
  uint64_t match_time_ns;
  uint64_t condition_time_ns;
} AGG_GROUP;

typedef struct
{
  YR_RULES* rules;
  uint32_t num_rules;
  uint32_t num_strings;

  RULE_META* metas;
  RULE_STATS* rule_stats;
  STRING_STATS* string_stats;

  SAMPLE_STATS* samples;
  size_t sample_count;
  size_t sample_capacity;

  uint64_t total_elapsed_ns;
  uint64_t total_rule_time_ns;
  uint64_t total_match_time_ns;
  uint64_t total_condition_time_ns;

  size_t successful_samples;
  size_t timeout_samples;
  size_t memory_limit_samples;
  size_t error_samples;

  bool* matched_scratch;
  uint64_t* hits_scratch;
  uint64_t* rule_cost_scratch;
  uint64_t* condition_cost_scratch;
  uint64_t* string_cost_scratch;
} REPORT;

typedef struct
{
  const YR_RULES* rules;
  bool* matched;
  uint64_t* hits;
  uint32_t matched_count;
} SCAN_CONTEXT;

typedef struct
{
  char* base_dir;
} INCLUDE_CONTEXT;

typedef struct
{
  uint32_t idx;
  uint64_t time_ns;
} time_rank_t;

static char* read_entire_file(const char* path);

static bool quiet = false;
static bool fast_scan = false;
static bool show_help = false;
static bool show_version = false;
static long timeout_seconds = 0;
static char* output_path = NULL;
static char* folded_path = NULL;
static char* memory_limit_arg = NULL;
static char* ext_vars[MAX_ARGS_EXT_VAR + 1];

#define USAGE_STRING \
  "Usage: yara-perf [OPTION]... RULES_FILE|RULES_DIR SAMPLES_FILE|SAMPLES_DIR"

static args_option_t options[] = {
    OPT_STRING(
        'o',
        _T("output"),
        &output_path,
        _T("write the JSON report to FILE (default: stdout), use - for stdout"),
        _T("FILE")),

    OPT_STRING(
        'F',
        _T("folded"),
        &folded_path,
        _T("write folded stacks to FILE (default: yara-perf.folded)"),
        _T("FILE")),

    OPT_LONG(
        't',
        _T("timeout"),
        &timeout_seconds,
        _T("per-sample scan timeout in SECONDS (0 disables it)"),
        _T("SECONDS")),

    OPT_STRING(
        'm',
        _T("memory-limit"),
        &memory_limit_arg,
        _T("per-sample address-space limit, e.g. 64M or 1073741824"),
        _T("BYTES")),

    OPT_STRING_MULTI(
        'd',
        _T("define"),
        &ext_vars,
        MAX_ARGS_EXT_VAR,
        _T("define external variable"),
        _T("VAR=VALUE")),

    OPT_BOOLEAN(
        'f',
        _T("fast-scan"),
        &fast_scan,
        _T("fast matching mode (same as yara -f)")),

    OPT_BOOLEAN('q', _T("quiet"), &quiet, _T("do not print progress information")),

    OPT_BOOLEAN('h', _T("help"), &show_help, _T("show this help and exit")),

    OPT_BOOLEAN(
        'v',
        _T("version"),
        &show_version,
        _T("show version information")),

    OPT_END(),
};

static void* xmalloc(size_t size)
{
  if (size == 0)
    size = 1;

  void* p = malloc(size);

  if (p == NULL)
  {
    fprintf(stderr, "yara-perf: out of memory\n");
    exit(EXIT_FAILURE);
  }

  return p;
}

static void* xcalloc(size_t count, size_t size)
{
  if (count == 0)
    count = 1;
  if (size == 0)
    size = 1;

  void* p = calloc(count, size);

  if (p == NULL)
  {
    fprintf(stderr, "yara-perf: out of memory\n");
    exit(EXIT_FAILURE);
  }

  return p;
}

static char* xstrdup(const char* s)
{
  char* result;

  if (s == NULL)
    return NULL;

  result = strdup(s);

  if (result == NULL)
  {
    fprintf(stderr, "yara-perf: out of memory\n");
    exit(EXIT_FAILURE);
  }

  return result;
}

static char* xasprintf(const char* fmt, ...)
{
  va_list args;
  char* result = NULL;

  va_start(args, fmt);

  if (vasprintf(&result, fmt, args) < 0)
    result = NULL;

  va_end(args);

  if (result == NULL)
  {
    fprintf(stderr, "yara-perf: out of memory\n");
    exit(EXIT_FAILURE);
  }

  return result;
}

static uint64_t now_ns(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);

  return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static bool path_list_add(PATH_LIST* list, const char* path)
{
  if (list->count == list->capacity)
  {
    size_t new_capacity = list->capacity == 0 ? 64 : list->capacity * 2;
    char** new_items = realloc(list->items, new_capacity * sizeof(char*));

    if (new_items == NULL)
      return false;

    list->items = new_items;
    list->capacity = new_capacity;
  }

  list->items[list->count++] = xstrdup(path);

  return true;
}

static int compare_paths(const void* a, const void* b)
{
  return strcmp(*(const char**) a, *(const char**) b);
}

static void path_list_sort(PATH_LIST* list)
{
  qsort(list->items, list->count, sizeof(char*), compare_paths);
}

static void path_list_destroy(PATH_LIST* list)
{
  for (size_t i = 0; i < list->count; i++) free(list->items[i]);

  free(list->items);
  list->items = NULL;
  list->count = 0;
  list->capacity = 0;
}

static bool same_file(const char* path_a, const char* path_b)
{
  struct stat a;
  struct stat b;

  if (path_a == NULL || path_b == NULL)
    return false;

  if (stat(path_a, &a) != 0 || stat(path_b, &b) != 0)
    return false;

  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static void path_list_remove_file(PATH_LIST* list, const char* path)
{
  if (path == NULL)
    return;

  for (size_t i = 0; i < list->count;)
  {
    if (!same_file(list->items[i], path))
    {
      i++;
      continue;
    }

    free(list->items[i]);

    for (size_t j = i; j + 1 < list->count; j++)
      list->items[j] = list->items[j + 1];

    list->count--;
  }
}

static char* canonical_path(const char* path)
{
  char* result = realpath(path, NULL);

  return result != NULL ? result : xstrdup(path);
}

static bool path_list_contains(const PATH_LIST* list, const char* path)
{
  for (size_t i = 0; i < list->count; i++)
  {
    if (strcmp(list->items[i], path) == 0)
      return true;
  }

  return false;
}

static char* resolve_include_path(
    const char* including_file,
    const char* base_dir,
    const char* include_name)
{
  struct stat st;
  char* candidate;

  if (include_name[0] == '/')
  {
    if (stat(include_name, &st) == 0 && S_ISREG(st.st_mode))
      return xstrdup(include_name);

    return NULL;
  }

  if (stat(include_name, &st) == 0 && S_ISREG(st.st_mode))
    return xstrdup(include_name);

  const char* slash = strrchr(including_file, '/');

  if (slash != NULL)
  {
    size_t dir_len = (size_t) (slash - including_file);

    candidate = xmalloc(dir_len + 1 + strlen(include_name) + 1);
    memcpy(candidate, including_file, dir_len);
    candidate[dir_len] = '/';
    strcpy(candidate + dir_len + 1, include_name);

    if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode))
      return candidate;

    free(candidate);
  }

  if (base_dir != NULL)
  {
    candidate = xasprintf("%s/%s", base_dir, include_name);

    if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode))
      return candidate;

    free(candidate);
  }

  return NULL;
}

static void collect_include_paths(
    const char* file,
    const char* base_dir,
    PATH_LIST* included,
    PATH_LIST* visited,
    int depth)
{
  if (depth > 32)
    return;

  char* canonical = canonical_path(file);

  if (path_list_contains(visited, canonical))
  {
    free(canonical);
    return;
  }

  path_list_add(visited, canonical);
  free(canonical);

  char* contents = read_entire_file(file);

  if (contents == NULL)
    return;

  char* line = contents;

  while (*line != '\0')
  {
    char* end = strchr(line, '\n');

    if (end != NULL)
      *end = '\0';

    char* p = line;

    while (*p == ' ' || *p == '\t') p++;

    if (strncmp(p, "include", 7) == 0 && isspace((unsigned char) p[7]))
    {
      p += 7;

      while (*p == ' ' || *p == '\t') p++;

      if (*p == '"')
      {
        char* include_name = ++p;
        char* quote = strchr(include_name, '"');

        if (quote != NULL)
        {
          *quote = '\0';

          char* resolved = resolve_include_path(file, base_dir, include_name);

          if (resolved != NULL)
          {
            char* resolved_canonical = canonical_path(resolved);

            if (!path_list_contains(included, resolved_canonical))
              path_list_add(included, resolved_canonical);

            free(resolved_canonical);

            collect_include_paths(
                resolved, base_dir, included, visited, depth + 1);
            free(resolved);
          }
        }
      }
    }

    if (end == NULL)
      break;

    line = end + 1;
  }

  free(contents);
}

static void remove_included_rule_files(PATH_LIST* files, const char* base_dir)
{
  PATH_LIST included = {0};
  PATH_LIST visited = {0};
  PATH_LIST canonical_files = {0};

  for (size_t i = 0; i < files->count; i++)
  {
    collect_include_paths(
        files->items[i], base_dir, &included, &visited, 0);

    char* canonical = canonical_path(files->items[i]);
    path_list_add(&canonical_files, canonical);
    free(canonical);
  }

  for (size_t i = 0; i < files->count;)
  {
    bool remove = path_list_contains(&included, canonical_files.items[i]);

    if (!remove)
    {
      for (size_t j = 0; j < i; j++)
      {
        if (strcmp(canonical_files.items[i], canonical_files.items[j]) == 0)
        {
          remove = true;
          break;
        }
      }
    }

    if (!remove)
    {
      i++;
      continue;
    }

    free(files->items[i]);
    free(canonical_files.items[i]);

    for (size_t j = i; j + 1 < files->count; j++)
    {
      files->items[j] = files->items[j + 1];
      canonical_files.items[j] = canonical_files.items[j + 1];
    }

    files->count--;
    canonical_files.count--;
  }

  path_list_destroy(&canonical_files);
  path_list_destroy(&visited);
  path_list_destroy(&included);
}

static bool has_rule_extension(const char* path)
{
  const char* dot = strrchr(path, '.');

  if (dot == NULL)
    return false;

  return strcasecmp(dot, ".yar") == 0 || strcasecmp(dot, ".yara") == 0 ||
         strcasecmp(dot, ".rule") == 0 || strcasecmp(dot, ".rules") == 0;
}

static bool collect_paths(
    const char* root,
    bool rules_only,
    int depth,
    PATH_LIST* list)
{
  struct stat st;

  if (depth > 64)
    return true;

  if (stat(root, &st) != 0)
  {
    fprintf(stderr, "yara-perf: can't stat %s: %s\n", root, strerror(errno));
    return false;
  }

  if (S_ISREG(st.st_mode))
  {
    if (!rules_only || depth == 0 || has_rule_extension(root))
      return path_list_add(list, root);

    return true;
  }

  if (!S_ISDIR(st.st_mode))
    return true;

  if (rules_only && depth > 0)
  {
    const char* base = strrchr(root, '/');

    base = base != NULL ? base + 1 : root;

    // Rule directories commonly keep include-only files in an include/
    // subdirectory. Compiling both the top-level file and its include creates
    // duplicate rules, so skip these conventional include directories.
    if (strcmp(base, "include") == 0 || strcmp(base, "includes") == 0)
      return true;
  }

  DIR* dir = opendir(root);

  if (dir == NULL)
  {
    fprintf(stderr, "yara-perf: can't open directory %s: %s\n", root, strerror(errno));
    return false;
  }

  struct dirent* entry;

  while ((entry = readdir(dir)) != NULL)
  {
    char* path;

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    path = xasprintf("%s/%s", root, entry->d_name);

    if (!collect_paths(path, rules_only, depth + 1, list))
    {
      free(path);
      closedir(dir);
      return false;
    }

    free(path);
  }

  closedir(dir);

  return true;
}

static char* read_entire_file(const char* path)
{
  FILE* file = fopen(path, "rb");

  if (file == NULL)
    return NULL;

  if (fseek(file, 0, SEEK_END) != 0)
  {
    fclose(file);
    return NULL;
  }

  long size = ftell(file);

  if (size < 0)
  {
    fclose(file);
    return NULL;
  }

  if (fseek(file, 0, SEEK_SET) != 0)
  {
    fclose(file);
    return NULL;
  }

  char* buffer = xmalloc((size_t) size + 1);

  if (fread(buffer, 1, (size_t) size, file) != (size_t) size)
  {
    fclose(file);
    free(buffer);
    return NULL;
  }

  buffer[size] = '\0';
  fclose(file);

  return buffer;
}

static const char* perf_include_callback(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data)
{
  INCLUDE_CONTEXT* context = (INCLUDE_CONTEXT*) user_data;
  char* result;

  (void) calling_rule_namespace;

  result = read_entire_file(include_name);

  if (result != NULL)
    return result;

  if (calling_rule_filename != NULL && include_name[0] != '/')
  {
    const char* slash = strrchr(calling_rule_filename, '/');

    if (slash != NULL)
    {
      size_t dir_len = (size_t) (slash - calling_rule_filename);
      char* relative = xmalloc(dir_len + 1 + strlen(include_name) + 1);

      memcpy(relative, calling_rule_filename, dir_len);
      relative[dir_len] = '/';
      strcpy(relative + dir_len + 1, include_name);

      result = read_entire_file(relative);
      free(relative);

      if (result != NULL)
        return result;
    }
  }

  if (context != NULL && context->base_dir != NULL &&
      include_name[0] != '/')
  {
    const char* relative_to = calling_rule_filename != NULL
                                  ? calling_rule_filename
                                  : include_name;
    const char* slash = strrchr(relative_to, '/');
    size_t dir_len = slash != NULL ? (size_t) (slash - relative_to) : 0;
    char* relative = xmalloc(
        strlen(context->base_dir) + 1 + dir_len + 1 + strlen(include_name) + 1);

    strcpy(relative, context->base_dir);
    size_t pos = strlen(relative);

    if (dir_len > 0)
    {
      relative[pos++] = '/';
      memcpy(relative + pos, relative_to, dir_len);
      pos += dir_len;
    }

    relative[pos++] = '/';
    strcpy(relative + pos, include_name);

    result = read_entire_file(relative);
    free(relative);

    if (result != NULL)
      return result;
  }

  return result;
}

static void perf_include_free(const char* ptr, void* user_data)
{
  (void) user_data;
  free((void*) ptr);
}

static void compile_callback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
  (void) rule;
  (void) user_data;

  fprintf(
      stderr,
      "%s:%d: %s: %s\n",
      file_name != NULL ? file_name : "<rules>",
      line_number,
      error_level == YARA_ERROR_LEVEL_ERROR ? "error" : "warning",
      message);
}

static bool compile_rules(
    const char* path,
    YR_RULES** rules,
    char** error_message)
{
  YR_COMPILER* compiler = NULL;
  PATH_LIST files = {0};
  INCLUDE_CONTEXT include_context = {0};
  struct stat root_stat;
  bool root_is_dir = false;
  bool result = false;
  int errors = 0;

  *rules = NULL;
  *error_message = NULL;

  if (!collect_paths(path, true, 0, &files))
    goto _exit;

  root_is_dir = stat(path, &root_stat) == 0 && S_ISDIR(root_stat.st_mode);

  if (root_is_dir)
    remove_included_rule_files(&files, path);

  path_list_sort(&files);

  if (files.count == 0)
  {
    *error_message = xstrdup("no rule files found");
    goto _exit;
  }

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    *error_message = xstrdup("can't create compiler");
    goto _exit;
  }

  if (root_is_dir)
  {
    include_context.base_dir = xstrdup(path);
  }
  else
  {
    const char* slash = strrchr(path, '/');

    if (slash == NULL)
    {
      include_context.base_dir = xstrdup(".");
    }
    else if (slash == path)
    {
      include_context.base_dir = xstrdup("/");
    }
    else
    {
      size_t len = (size_t) (slash - path);
      include_context.base_dir = xmalloc(len + 1);
      memcpy(include_context.base_dir, path, len);
      include_context.base_dir[len] = '\0';
    }
  }

  yr_compiler_set_callback(compiler, compile_callback, NULL);
  yr_compiler_set_include_callback(
      compiler, perf_include_callback, perf_include_free, &include_context);

  if (!quiet)
    fprintf(stderr, "yara-perf: compiling %zu rule file(s)\n", files.count);

  for (size_t i = 0; i < files.count; i++)
  {
    FILE* file = fopen(files.items[i], "r");

    if (file == NULL)
    {
      *error_message = xasprintf("can't open %s: %s", files.items[i], strerror(errno));
      goto _exit;
    }

    errors = yr_compiler_add_file(compiler, file, NULL, files.items[i]);
    fclose(file);

    if (errors > 0)
    {
      *error_message = xasprintf("failed to compile %s", files.items[i]);
      goto _exit;
    }
  }

  if (ext_vars[0] != NULL)
    define_external_variables(ext_vars, NULL, compiler);

  int rc = yr_compiler_get_rules(compiler, rules);

  if (rc != ERROR_SUCCESS)
  {
    *error_message = xasprintf("yr_compiler_get_rules failed with error %d", rc);
    goto _exit;
  }

  result = true;

_exit:
  if (compiler != NULL)
    yr_compiler_destroy(compiler);

  free(include_context.base_dir);
  path_list_destroy(&files);

  return result;
}

static const char* meta_as_string(YR_META* meta, char* buffer, size_t size)
{
  switch (meta->type)
  {
  case META_TYPE_STRING:
    return meta->string;

  case META_TYPE_INTEGER:
    snprintf(buffer, size, "%" PRId64, meta->integer);
    return buffer;

  case META_TYPE_BOOLEAN:
    return meta->integer ? "true" : "false";
  }

  return "(none)";
}

static const char* find_meta(
    YR_RULE* rule,
    const char* const* names,
    size_t names_count,
    char* buffer,
    size_t buffer_size)
{
  YR_META* meta;

  for (size_t i = 0; i < names_count; i++)
  {
    yr_rule_metas_foreach(rule, meta)
    {
      if (meta->identifier != NULL &&
          strcasecmp(meta->identifier, names[i]) == 0)
      {
        return meta_as_string(meta, buffer, buffer_size);
      }
    }
  }

  return NULL;
}

static const char* find_tag_value(
    YR_RULE* rule,
    const char* prefix,
    char* buffer,
    size_t buffer_size)
{
  const char* tag;
  size_t prefix_len = strlen(prefix);

  yr_rule_tags_foreach(rule, tag)
  {
    if (strncasecmp(tag, prefix, prefix_len) == 0)
    {
      snprintf(buffer, buffer_size, "%s", tag + prefix_len);
      return buffer;
    }
  }

  return NULL;
}

static RULE_META build_rule_meta(YR_RULE* rule)
{
  RULE_META result;
  char buffer[128];
  const char* tag;
  const char* value;

  memset(&result, 0, sizeof(result));

  result.rule = rule;
  result.identifier = rule->identifier;
  result.ns = rule->ns != NULL ? rule->ns->name : "default";

  size_t tag_count = 0;

  yr_rule_tags_foreach(rule, tag) tag_count++;

  result.tags = xcalloc(tag_count > 0 ? tag_count : 1, sizeof(char*));
  result.tag_count = tag_count;

  size_t tag_idx = 0;

  yr_rule_tags_foreach(rule, tag) result.tags[tag_idx++] = xstrdup(tag);

  static const char* author_names[] = {"author"};
  static const char* severity_names[] = {
      "severity", "threat_level", "threat-level", "level", "risk"};

  value = find_meta(
      rule,
      author_names,
      sizeof(author_names) / sizeof(author_names[0]),
      buffer,
      sizeof(buffer));

  if (value == NULL)
    value = find_tag_value(rule, "author:", buffer, sizeof(buffer));

  if (value == NULL)
    value = find_tag_value(rule, "author=", buffer, sizeof(buffer));

  result.author = xstrdup(value != NULL ? value : "(none)");

  value = find_meta(
      rule,
      severity_names,
      sizeof(severity_names) / sizeof(severity_names[0]),
      buffer,
      sizeof(buffer));

  if (value == NULL)
    value = find_tag_value(rule, "severity:", buffer, sizeof(buffer));

  if (value == NULL)
    value = find_tag_value(rule, "threat_level:", buffer, sizeof(buffer));

  result.severity = xstrdup(value != NULL ? value : "(none)");

  return result;
}

static void free_rule_meta(RULE_META* meta)
{
  for (size_t i = 0; i < meta->tag_count; i++) free(meta->tags[i]);

  free(meta->tags);
  free(meta->author);
  free(meta->severity);
}

static bool report_init(REPORT* report, YR_RULES* rules)
{
  memset(report, 0, sizeof(REPORT));

  report->rules = rules;
  report->num_rules = rules->num_rules;
  report->num_strings = rules->num_strings;

  report->metas = xcalloc(report->num_rules, sizeof(RULE_META));
  report->rule_stats = xcalloc(report->num_rules, sizeof(RULE_STATS));
  report->string_stats = xcalloc(report->num_strings, sizeof(STRING_STATS));

  report->matched_scratch = xcalloc(report->num_rules, sizeof(bool));
  report->hits_scratch = xcalloc(report->num_strings, sizeof(uint64_t));
  report->rule_cost_scratch = xcalloc(report->num_rules, sizeof(uint64_t));
  report->condition_cost_scratch = xcalloc(report->num_rules, sizeof(uint64_t));
  report->string_cost_scratch = xcalloc(report->num_strings, sizeof(uint64_t));

  for (uint32_t i = 0; i < report->num_rules; i++)
    report->metas[i] = build_rule_meta(&rules->rules_table[i]);

  return true;
}

static void report_destroy(REPORT* report)
{
  for (uint32_t i = 0; i < report->num_rules; i++)
    free_rule_meta(&report->metas[i]);

  for (size_t i = 0; i < report->sample_count; i++)
  {
    free(report->samples[i].path);
    free(report->samples[i].matched_rules);
  }

  free(report->samples);
  free(report->metas);
  free(report->rule_stats);
  free(report->string_stats);
  free(report->matched_scratch);
  free(report->hits_scratch);
  free(report->rule_cost_scratch);
  free(report->condition_cost_scratch);
  free(report->string_cost_scratch);
}

static SAMPLE_STATS* report_add_sample(REPORT* report, const char* path)
{
  if (report->sample_count == report->sample_capacity)
  {
    size_t new_capacity = report->sample_capacity == 0 ? 64
                                                       : report->sample_capacity * 2;
    SAMPLE_STATS* new_samples = realloc(
        report->samples, new_capacity * sizeof(SAMPLE_STATS));

    if (new_samples == NULL)
    {
      fprintf(stderr, "yara-perf: out of memory\n");
      exit(EXIT_FAILURE);
    }

    report->samples = new_samples;
    report->sample_capacity = new_capacity;
  }

  SAMPLE_STATS* sample = &report->samples[report->sample_count++];

  memset(sample, 0, sizeof(SAMPLE_STATS));
  sample->path = xstrdup(path);
  sample->status = STATUS_OK;

  return sample;
}

static int scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  SCAN_CONTEXT* scan_context = (SCAN_CONTEXT*) user_data;

  switch (message)
  {
  case CALLBACK_MSG_RULE_MATCHING:
  {
    YR_RULE* rule = (YR_RULE*) message_data;
    ptrdiff_t idx = rule - context->rules->rules_table;

    if (idx >= 0 && idx < context->rules->num_rules &&
        !scan_context->matched[idx])
    {
      scan_context->matched[idx] = true;
      scan_context->matched_count++;
    }

    return CALLBACK_CONTINUE;
  }

  case CALLBACK_MSG_SCAN_FINISHED:
  {
    for (uint32_t i = 0; i < context->rules->num_strings; i++)
    {
      YR_STRING* string = &context->rules->strings_table[i];
      YR_MATCH* match;

      yr_string_matches_foreach(context, string, match)
      scan_context->hits[i]++;
    }

    return CALLBACK_CONTINUE;
  }

  case CALLBACK_MSG_TOO_SLOW_SCANNING:
  case CALLBACK_MSG_TOO_MANY_MATCHES:
  case CALLBACK_MSG_IMPORT_MODULE:
  case CALLBACK_MSG_MODULE_IMPORTED:
  case CALLBACK_MSG_CONSOLE_LOG:
    return CALLBACK_CONTINUE;
  }

  return CALLBACK_CONTINUE;
}

static uint64_t scaled_time(uint64_t time_ns, uint32_t atom_matches, uint32_t samples)
{
  if (samples == 0 || atom_matches == 0)
    return 0;

  long double value = (long double) time_ns * (long double) atom_matches /
                      (long double) samples;

  if (value > (long double) UINT64_MAX)
    return UINT64_MAX;

  return (uint64_t) (value + 0.5L);
}

static bool parse_size(const char* text, uint64_t* value)
{
  char* end = NULL;
  unsigned long long parsed = strtoull(text, &end, 0);

  if (end == text)
    return false;

  uint64_t multiplier = 1;

  if (*end != '\0')
  {
    if (strcasecmp(end, "K") == 0 || strcasecmp(end, "KB") == 0 ||
        strcasecmp(end, "KIB") == 0)
      multiplier = 1024ULL;
    else if (strcasecmp(end, "M") == 0 || strcasecmp(end, "MB") == 0 ||
             strcasecmp(end, "MIB") == 0)
      multiplier = 1024ULL * 1024ULL;
    else if (strcasecmp(end, "G") == 0 || strcasecmp(end, "GB") == 0 ||
             strcasecmp(end, "GIB") == 0)
      multiplier = 1024ULL * 1024ULL * 1024ULL;
    else
      return false;
  }

  if (parsed > UINT64_MAX / multiplier)
    return false;

  *value = (uint64_t) parsed * multiplier;

  return true;
}

static bool apply_memory_limit(uint64_t limit, struct rlimit* old_limit)
{
#ifdef RLIMIT_AS
  if (limit == 0)
    return true;

  if (getrlimit(RLIMIT_AS, old_limit) != 0)
    return false;

  struct rlimit new_limit = *old_limit;

  new_limit.rlim_cur = (rlim_t) limit;

  if (new_limit.rlim_max != RLIM_INFINITY && new_limit.rlim_cur > new_limit.rlim_max)
    new_limit.rlim_cur = new_limit.rlim_max;

  return setrlimit(RLIMIT_AS, &new_limit) == 0;
#else
  (void) limit;
  (void) old_limit;
  return limit == 0;
#endif
}

static void restore_memory_limit(const struct rlimit* old_limit)
{
#ifdef RLIMIT_AS
  setrlimit(RLIMIT_AS, old_limit);
#else
  (void) old_limit;
#endif
}

static void folded_escape(FILE* out, const char* text)
{
  for (const char* p = text; *p != '\0'; p++)
  {
    if (*p == ';' || *p == '\n' || *p == '\r')
      fputc('_', out);
    else
      fputc(*p, out);
  }
}

static void folded_value(FILE* out, uint64_t ns)
{
  uint64_t value = (ns + 999) / 1000;

  if (value == 0)
    value = 1;

  fprintf(out, " %" PRIu64 "\n", value);
}

static void folded_sample(
    FILE* out,
    const char* path,
    uint64_t elapsed_ns,
    const char* status)
{
  if (out == NULL)
    return;

  if (strcmp(status, STATUS_OK) == 0)
    return;

  fprintf(out, "yara;");
  folded_escape(out, path);
  fprintf(out, ";status;");
  folded_escape(out, status);
  folded_value(out, elapsed_ns);
}

static void folded_rule_leaf(
    FILE* out,
    const char* path,
    const char* ns,
    const char* rule,
    const char* leaf,
    uint64_t ns_value)
{
  if (out == NULL || ns_value == 0)
    return;

  fprintf(out, "yara;");
  folded_escape(out, path);
  fprintf(out, ";");
  folded_escape(out, ns);
  fprintf(out, ":");
  folded_escape(out, rule);
  fprintf(out, ";");
  folded_escape(out, leaf);
  folded_value(out, ns_value);
}

static void account_sample(
    REPORT* report,
    YR_SCANNER* scanner,
    SCAN_CONTEXT* scan_context,
    FILE* folded)
{
  YR_RULES* rules = scanner->rules;
  YR_PROFILING_INFO* rule_profile = scanner->profiling_info;
  YR_STRING_PROFILING_INFO* string_profile = scanner->string_profiling_info;

  memset(report->string_cost_scratch, 0, report->num_strings * sizeof(uint64_t));
  memset(report->rule_cost_scratch, 0, report->num_rules * sizeof(uint64_t));
  memset(report->condition_cost_scratch, 0, report->num_rules * sizeof(uint64_t));

  for (uint32_t i = 0; i < report->num_strings; i++)
  {
    uint64_t cost = 0;

    if (string_profile != NULL)
    {
      cost = scaled_time(
          string_profile[i].match_time,
          string_profile[i].atom_matches,
          string_profile[i].match_samples);
    }

    report->string_cost_scratch[i] = cost;
    report->string_stats[i].match_time_ns += cost;
    report->string_stats[i].atom_matches += string_profile != NULL
                                                ? string_profile[i].atom_matches
                                                : 0;
    report->string_stats[i].match_samples += string_profile != NULL
                                                ? string_profile[i].match_samples
                                                : 0;
    report->string_stats[i].hit_count += scan_context->hits[i];
  }

  for (uint32_t i = 0; i < report->num_rules; i++)
  {
    YR_RULE* rule = &rules->rules_table[i];
    YR_STRING* string;
    uint64_t match_time = 0;

    yr_rule_strings_foreach(rule, string)
    {
      match_time += report->string_cost_scratch[string->idx];
    }

    uint64_t condition_time = rule_profile != NULL ? rule_profile[i].exec_time : 0;

    report->rule_cost_scratch[i] = match_time + condition_time;
    report->condition_cost_scratch[i] = condition_time;

    report->rule_stats[i].match_time_ns += match_time;
    report->rule_stats[i].condition_time_ns += condition_time;
    report->rule_stats[i].total_time_ns += match_time + condition_time;
    report->rule_stats[i].atom_matches += rule_profile != NULL
                                              ? rule_profile[i].atom_matches
                                              : 0;
    report->rule_stats[i].match_samples += rule_profile != NULL
                                               ? rule_profile[i].match_samples
                                               : 0;

    if (scan_context->matched[i])
      report->rule_stats[i].matched_samples++;

    report->total_match_time_ns += match_time;
    report->total_condition_time_ns += condition_time;
    report->total_rule_time_ns += match_time + condition_time;

    if (folded != NULL)
    {
      yr_rule_strings_foreach(rule, string)
      {
        folded_rule_leaf(
            folded,
            report->samples[report->sample_count - 1].path,
            report->metas[i].ns,
            report->metas[i].identifier,
            string->identifier,
            report->string_cost_scratch[string->idx]);
      }

      folded_rule_leaf(
          folded,
          report->samples[report->sample_count - 1].path,
          report->metas[i].ns,
          report->metas[i].identifier,
          "condition",
          condition_time);
    }
  }
}

static bool scan_sample(
    REPORT* report,
    const char* path,
    uint64_t memory_limit,
    FILE* folded)
{
  SCAN_CONTEXT scan_context;
  YR_SCANNER* scanner = NULL;
  SAMPLE_STATS* sample = report_add_sample(report, path);
  struct stat st;
  struct rlimit old_limit;
  bool limit_applied = false;
  int result;

  memset(&scan_context, 0, sizeof(scan_context));
  scan_context.rules = report->rules;
  scan_context.matched = report->matched_scratch;
  scan_context.hits = report->hits_scratch;

  memset(report->matched_scratch, 0, report->num_rules * sizeof(bool));
  memset(report->hits_scratch, 0, report->num_strings * sizeof(uint64_t));

  if (stat(path, &st) == 0)
    sample->size = (uint64_t) st.st_size;

  result = yr_scanner_create(report->rules, &scanner);

  if (result != ERROR_SUCCESS)
  {
    sample->status = STATUS_ERROR;
    sample->error_code = result;
    report->error_samples++;
    return false;
  }

  if ((scanner->profiling_info == NULL && report->num_rules > 0) ||
      (scanner->string_profiling_info == NULL && report->num_strings > 0))
  {
    fprintf(
        stderr,
        "yara-perf: profiling support is not available in the linked libyara\n");
    yr_scanner_destroy(scanner);
    exit(EXIT_FAILURE);
  }

  yr_scanner_set_callback(scanner, scan_callback, &scan_context);
  yr_scanner_set_flags(
      scanner,
      SCAN_FLAGS_REPORT_RULES_MATCHING |
          (fast_scan ? SCAN_FLAGS_FAST_MODE : 0));

  if (timeout_seconds > 0)
    yr_scanner_set_timeout(scanner, (int) timeout_seconds);

  if (memory_limit > 0)
  {
    if (!apply_memory_limit(memory_limit, &old_limit))
    {
      fprintf(
          stderr,
          "yara-perf: can't apply memory limit: %s\n",
          strerror(errno));
      yr_scanner_destroy(scanner);
      exit(EXIT_FAILURE);
    }

    limit_applied = true;
  }

  uint64_t start = now_ns();
  result = yr_scanner_scan_file(scanner, path);
  uint64_t elapsed = now_ns() - start;

  if (limit_applied)
    restore_memory_limit(&old_limit);

  sample->elapsed_ns = elapsed;
  report->total_elapsed_ns += elapsed;

  if (result == ERROR_SCAN_TIMEOUT)
  {
    sample->status = STATUS_TIMEOUT;
    report->timeout_samples++;
    folded_sample(folded, path, elapsed, STATUS_TIMEOUT);
  }
  else if (
      memory_limit > 0 &&
      (result == ERROR_INSUFFICIENT_MEMORY || result == ERROR_COULD_NOT_MAP_FILE))
  {
    sample->status = STATUS_MEMORY_LIMIT;
    sample->error_code = result;
    report->memory_limit_samples++;
    folded_sample(folded, path, elapsed, STATUS_MEMORY_LIMIT);
  }
  else if (result != ERROR_SUCCESS)
  {
    sample->status = STATUS_ERROR;
    sample->error_code = result;
    report->error_samples++;
    folded_sample(folded, path, elapsed, STATUS_ERROR);
  }
  else
  {
    report->successful_samples++;

    if (scan_context.matched_count > 0)
    {
      sample->matched_rules = xcalloc(
          scan_context.matched_count, sizeof(uint32_t));

      for (uint32_t i = 0; i < report->num_rules; i++)
      {
        if (scan_context.matched[i])
          sample->matched_rules[sample->matched_count++] = i;
      }
    }

    account_sample(report, scanner, &scan_context, folded);

    uint64_t folded_total = 0;

    for (uint32_t i = 0; i < report->num_rules; i++)
      folded_total += report->rule_cost_scratch[i];

    if (folded != NULL && elapsed > folded_total)
    {
      folded_rule_leaf(
          folded, path, "yara", "scan", "overhead", elapsed - folded_total);
    }

    folded_sample(folded, path, elapsed, STATUS_OK);
  }

  yr_scanner_destroy(scanner);

  return true;
}

static void json_string(FILE* out, const char* text)
{
  if (text == NULL)
  {
    fputs("null", out);
    return;
  }

  fputc('"', out);

  for (const unsigned char* p = (const unsigned char*) text; *p != '\0'; p++)
  {
    switch (*p)
    {
    case '"':
      fputs("\\\"", out);
      break;
    case '\\':
      fputs("\\\\", out);
      break;
    case '\b':
      fputs("\\b", out);
      break;
    case '\f':
      fputs("\\f", out);
      break;
    case '\n':
      fputs("\\n", out);
      break;
    case '\r':
      fputs("\\r", out);
      break;
    case '\t':
      fputs("\\t", out);
      break;
    default:
      if (*p < 0x20)
        fprintf(out, "\\u%04x", *p);
      else
        fputc(*p, out);
      break;
    }
  }

  fputc('"', out);
}

static void json_key(FILE* out, const char* key)
{
  json_string(out, key);
  fputs(": ", out);
}

static int compare_time_rank_desc(const void* a, const void* b)
{
  const time_rank_t* ra = (const time_rank_t*) a;
  const time_rank_t* rb = (const time_rank_t*) b;

  if (ra->time_ns < rb->time_ns)
    return 1;
  if (ra->time_ns > rb->time_ns)
    return -1;
  return (int) ra->idx - (int) rb->idx;
}

static int compare_sample_desc(const void* a, const void* b)
{
  const SAMPLE_STATS* sa = *(const SAMPLE_STATS* const*) a;
  const SAMPLE_STATS* sb = *(const SAMPLE_STATS* const*) b;

  if (sa->elapsed_ns < sb->elapsed_ns)
    return 1;
  if (sa->elapsed_ns > sb->elapsed_ns)
    return -1;
  return strcmp(sa->path, sb->path);
}

static int compare_groups_desc(const void* a, const void* b)
{
  const AGG_GROUP* ga = (const AGG_GROUP*) a;
  const AGG_GROUP* gb = (const AGG_GROUP*) b;

  if (ga->total_time_ns < gb->total_time_ns)
    return 1;
  if (ga->total_time_ns > gb->total_time_ns)
    return -1;
  return strcmp(ga->key, gb->key);
}

static AGG_GROUP* find_or_add_group(
    AGG_GROUP** groups,
    size_t* count,
    size_t* capacity,
    const char* key)
{
  for (size_t i = 0; i < *count; i++)
  {
    if (strcmp((*groups)[i].key, key) == 0)
      return &(*groups)[i];
  }

  if (*count == *capacity)
  {
    size_t new_capacity = *capacity == 0 ? 16 : *capacity * 2;
    AGG_GROUP* new_groups = realloc(
        *groups, new_capacity * sizeof(AGG_GROUP));

    if (new_groups == NULL)
    {
      fprintf(stderr, "yara-perf: out of memory\n");
      exit(EXIT_FAILURE);
    }

    *groups = new_groups;
    *capacity = new_capacity;
  }

  AGG_GROUP* group = &(*groups)[(*count)++];

  memset(group, 0, sizeof(AGG_GROUP));
  group->key = xstrdup(key);

  return group;
}

static void collect_group(
    REPORT* report,
    AGG_GROUP** groups,
    size_t* count,
    size_t* capacity,
    const char* key,
    uint32_t rule_idx)
{
  AGG_GROUP* group = find_or_add_group(groups, count, capacity, key);
  RULE_STATS* stats = &report->rule_stats[rule_idx];

  group->rule_count++;
  group->matched_samples += stats->matched_samples;
  group->total_time_ns += stats->total_time_ns;
  group->match_time_ns += stats->match_time_ns;
  group->condition_time_ns += stats->condition_time_ns;
}

static void build_aggregates(
    REPORT* report,
    AGG_GROUP** tags,
    size_t* tag_count,
    AGG_GROUP** authors,
    size_t* author_count,
    AGG_GROUP** severities,
    size_t* severity_count)
{
  size_t tag_capacity = 0;
  size_t author_capacity = 0;
  size_t severity_capacity = 0;

  *tags = NULL;
  *authors = NULL;
  *severities = NULL;
  *tag_count = 0;
  *author_count = 0;
  *severity_count = 0;

  for (uint32_t i = 0; i < report->num_rules; i++)
  {
    RULE_META* meta = &report->metas[i];

    for (size_t j = 0; j < meta->tag_count; j++)
    {
      collect_group(
          report, tags, tag_count, &tag_capacity, meta->tags[j], i);
    }

    collect_group(
        report,
        authors,
        author_count,
        &author_capacity,
        meta->author,
        i);

    collect_group(
        report,
        severities,
        severity_count,
        &severity_capacity,
        meta->severity,
        i);
  }

  if (*tag_count > 1)
    qsort(*tags, *tag_count, sizeof(AGG_GROUP), compare_groups_desc);
  if (*author_count > 1)
    qsort(*authors, *author_count, sizeof(AGG_GROUP), compare_groups_desc);
  if (*severity_count > 1)
    qsort(
        *severities,
        *severity_count,
        sizeof(AGG_GROUP),
        compare_groups_desc);
}

static void free_groups(AGG_GROUP* groups, size_t count)
{
  for (size_t i = 0; i < count; i++) free(groups[i].key);
  free(groups);
}

static void write_groups(
    FILE* out,
    const char* name,
    AGG_GROUP* groups,
    size_t count,
    uint64_t total_time_ns)
{
  fprintf(out, "    ");
  json_key(out, name);
  fputs("[\n", out);

  for (size_t i = 0; i < count; i++)
  {
    fprintf(out, "      {\n");
    fprintf(out, "        ");
    json_key(out, "key");
    json_string(out, groups[i].key);
    fprintf(out, ",\n        ");
    json_key(out, "rule_count");
    fprintf(out, "%" PRIu64 ",\n", groups[i].rule_count);
    fprintf(out, "        ");
    json_key(out, "matched_samples");
    fprintf(out, "%" PRIu64 ",\n", groups[i].matched_samples);
    fprintf(out, "        ");
    json_key(out, "total_time_ns");
    fprintf(out, "%" PRIu64 ",\n", groups[i].total_time_ns);
    fprintf(out, "        ");
    json_key(out, "time_share");
    fprintf(
        out,
        "%.6f,\n",
        total_time_ns > 0
            ? (double) groups[i].total_time_ns / (double) total_time_ns
            : 0.0);
    fprintf(out, "        ");
    json_key(out, "match_time_ns");
    fprintf(out, "%" PRIu64 ",\n", groups[i].match_time_ns);
    fprintf(out, "        ");
    json_key(out, "condition_time_ns");
    fprintf(out, "%" PRIu64 "\n", groups[i].condition_time_ns);
    fprintf(out, "      }%s\n", i + 1 < count ? "," : "");
  }

  fputs("    ]", out);
}

static void write_rule(
    FILE* out,
    REPORT* report,
    uint32_t rule_idx,
    time_rank_t* string_order)
{
  RULE_META* meta = &report->metas[rule_idx];
  RULE_STATS* stats = &report->rule_stats[rule_idx];
  YR_RULE* rule = meta->rule;
  YR_STRING* string;
  size_t string_count = 0;
  uint64_t total_hits = 0;

  yr_rule_strings_foreach(rule, string)
  {
    string_order[string_count].idx = string->idx;
    string_order[string_count].time_ns =
        report->string_stats[string->idx].match_time_ns;
    total_hits += report->string_stats[string->idx].hit_count;
    string_count++;
  }

  if (string_count > 1)
  {
    qsort(
        string_order,
        string_count,
        sizeof(time_rank_t),
        compare_time_rank_desc);
  }

  fprintf(out, "    {\n");
  fprintf(out, "      ");
  json_key(out, "namespace");
  json_string(out, meta->ns);
  fprintf(out, ",\n      ");
  json_key(out, "identifier");
  json_string(out, meta->identifier);
  fprintf(out, ",\n      ");
  json_key(out, "tags");
  fputc('[', out);

  for (size_t i = 0; i < meta->tag_count; i++)
  {
    if (i > 0)
      fputs(", ", out);
    json_string(out, meta->tags[i]);
  }

  fputs("],\n      ", out);
  json_key(out, "author");
  json_string(out, meta->author);
  fprintf(out, ",\n      ");
  json_key(out, "severity");
  json_string(out, meta->severity);
  fprintf(out, ",\n      ");
  json_key(out, "matched_samples");
  fprintf(out, "%" PRIu64 ",\n", stats->matched_samples);
  fprintf(out, "      ");
  json_key(out, "total_time_ns");
  fprintf(out, "%" PRIu64 ",\n", stats->total_time_ns);
  fprintf(out, "      ");
  json_key(out, "match_time_ns");
  fprintf(out, "%" PRIu64 ",\n", stats->match_time_ns);
  fprintf(out, "      ");
  json_key(out, "condition_time_ns");
  fprintf(out, "%" PRIu64 ",\n", stats->condition_time_ns);
  fprintf(out, "      ");
  json_key(out, "atom_matches");
  fprintf(out, "%" PRIu64 ",\n", stats->atom_matches);
  fprintf(out, "      ");
  json_key(out, "match_samples");
  fprintf(out, "%" PRIu64 ",\n", stats->match_samples);
  fprintf(out, "      ");
  json_key(out, "total_string_hits");
  fprintf(out, "%" PRIu64 ",\n", total_hits);
  fprintf(out, "      ");
  json_key(out, "strings");
  fputs("[\n", out);

  for (size_t i = 0; i < string_count; i++)
  {
    uint32_t idx = string_order[i].idx;
    STRING_STATS* string_stats = &report->string_stats[idx];
    YR_STRING* current = &report->rules->strings_table[idx];
    double share = stats->match_time_ns > 0
                       ? (double) string_stats->match_time_ns /
                             (double) stats->match_time_ns
                       : 0.0;

    fprintf(out, "        {\n");
    fprintf(out, "          ");
    json_key(out, "identifier");
    json_string(out, current->identifier);
    fprintf(out, ",\n          ");
    json_key(out, "hit_count");
    fprintf(out, "%" PRIu64 ",\n", string_stats->hit_count);
    fprintf(out, "          ");
    json_key(out, "atom_matches");
    fprintf(out, "%" PRIu64 ",\n", string_stats->atom_matches);
    fprintf(out, "          ");
    json_key(out, "match_samples");
    fprintf(out, "%" PRIu64 ",\n", string_stats->match_samples);
    fprintf(out, "          ");
    json_key(out, "match_time_ns");
    fprintf(out, "%" PRIu64 ",\n", string_stats->match_time_ns);
    fprintf(out, "          ");
    json_key(out, "time_share");
    fprintf(out, "%.6f\n", share);
    fprintf(out, "        }%s\n", i + 1 < string_count ? "," : "");
  }

  fputs("      ]\n", out);
  fputs("    }", out);
}

static void write_report(
    FILE* out,
    REPORT* report,
    const char* rules_path,
    const char* samples_path,
    uint64_t memory_limit)
{
  time_rank_t* rule_order = xcalloc(
      report->num_rules > 0 ? report->num_rules : 1, sizeof(time_rank_t));
  time_rank_t* string_order = xcalloc(
      report->num_strings > 0 ? report->num_strings : 1, sizeof(time_rank_t));
  SAMPLE_STATS** sample_order = xcalloc(
      report->sample_count > 0 ? report->sample_count : 1,
      sizeof(SAMPLE_STATS*));
  AGG_GROUP* tags = NULL;
  AGG_GROUP* authors = NULL;
  AGG_GROUP* severities = NULL;
  size_t tag_count = 0;
  size_t author_count = 0;
  size_t severity_count = 0;

  for (uint32_t i = 0; i < report->num_rules; i++)
  {
    rule_order[i].idx = i;
    rule_order[i].time_ns = report->rule_stats[i].total_time_ns;
  }

  if (report->num_rules > 1)
  {
    qsort(
        rule_order,
        report->num_rules,
        sizeof(time_rank_t),
        compare_time_rank_desc);
  }

  for (size_t i = 0; i < report->sample_count; i++)
    sample_order[i] = &report->samples[i];

  if (report->sample_count > 1)
  {
    qsort(
        sample_order,
        report->sample_count,
        sizeof(SAMPLE_STATS*),
        compare_sample_desc);
  }

  build_aggregates(
      report,
      &tags,
      &tag_count,
      &authors,
      &author_count,
      &severities,
      &severity_count);

  fprintf(out, "{\n");
  fprintf(out, "  ");
  json_key(out, "tool");
  json_string(out, "yara-perf");
  fprintf(out, ",\n  ");
  json_key(out, "yara_version");
  json_string(out, YR_VERSION);
  fprintf(out, ",\n  ");
  json_key(out, "rules_path");
  json_string(out, rules_path);
  fprintf(out, ",\n  ");
  json_key(out, "samples_path");
  json_string(out, samples_path);
  fprintf(out, ",\n  ");
  json_key(out, "options");
  fprintf(out, "{\n");
  fprintf(out, "    ");
  json_key(out, "timeout_seconds");
  fprintf(out, "%ld,\n", timeout_seconds);
  fprintf(out, "    ");
  json_key(out, "memory_limit_bytes");
  fprintf(out, "%" PRIu64 ",\n", memory_limit);
  fprintf(out, "    ");
  json_key(out, "fast_scan");
  fprintf(out, "%s\n", fast_scan ? "true" : "false");
  fprintf(out, "  },\n  ");
  json_key(out, "sample_count");
  fprintf(out, "%zu,\n", report->sample_count);
  fprintf(out, "  ");
  json_key(out, "successful_samples");
  fprintf(out, "%zu,\n", report->successful_samples);
  fprintf(out, "  ");
  json_key(out, "timeout_count");
  fprintf(out, "%zu,\n", report->timeout_samples);
  fprintf(out, "  ");
  json_key(out, "memory_limit_count");
  fprintf(out, "%zu,\n", report->memory_limit_samples);
  fprintf(out, "  ");
  json_key(out, "error_count");
  fprintf(out, "%zu,\n", report->error_samples);
  fprintf(out, "  ");
  json_key(out, "total_elapsed_ns");
  fprintf(out, "%" PRIu64 ",\n", report->total_elapsed_ns);
  fprintf(out, "  ");
  json_key(out, "total_rule_time_ns");
  fprintf(out, "%" PRIu64 ",\n", report->total_rule_time_ns);
  fprintf(out, "  ");
  json_key(out, "scan_overhead_ns");
  fprintf(
      out,
      "%" PRIu64 ",\n",
      report->total_elapsed_ns > report->total_rule_time_ns
          ? report->total_elapsed_ns - report->total_rule_time_ns
          : 0);

  fprintf(out, "  ");
  json_key(out, "rules");
  fputs("[\n", out);

  for (uint32_t i = 0; i < report->num_rules; i++)
  {
    write_rule(out, report, rule_order[i].idx, string_order);
    fprintf(out, "%s\n", i + 1 < report->num_rules ? "," : "");
  }

  fputs("  ],\n", out);
  fprintf(out, "  ");
  json_key(out, "aggregates");
  fputs("{\n", out);
  write_groups(
      out, "tags", tags, tag_count, report->total_rule_time_ns);
  fputs(",\n", out);
  write_groups(
      out, "authors", authors, author_count, report->total_rule_time_ns);
  fputs(",\n", out);
  write_groups(
      out,
      "severities",
      severities,
      severity_count,
      report->total_rule_time_ns);
  fputs("\n  },\n", out);

  size_t slow_count = report->sample_count < 20 ? report->sample_count : 20;

  fprintf(out, "  ");
  json_key(out, "slowest_samples");
  fputs("[\n", out);

  for (size_t i = 0; i < slow_count; i++)
  {
    SAMPLE_STATS* sample = sample_order[i];

    fprintf(out, "    {\n");
    fprintf(out, "      ");
    json_key(out, "path");
    json_string(out, sample->path);
    fprintf(out, ",\n      ");
    json_key(out, "size");
    fprintf(out, "%" PRIu64 ",\n", sample->size);
    fprintf(out, "      ");
    json_key(out, "elapsed_ns");
    fprintf(out, "%" PRIu64 ",\n", sample->elapsed_ns);
    fprintf(out, "      ");
    json_key(out, "status");
    json_string(out, sample->status);
    fprintf(out, ",\n      ");
    json_key(out, "matched_rule_count");
    fprintf(out, "%u,\n", sample->matched_count);
    fprintf(out, "      ");
    json_key(out, "matched_rules");
    fputs("[", out);

    for (uint32_t j = 0; j < sample->matched_count; j++)
    {
      uint32_t rule_idx = sample->matched_rules[j];
      char* qualified = xasprintf(
          "%s:%s",
          report->metas[rule_idx].ns,
          report->metas[rule_idx].identifier);

      if (j > 0)
        fputs(", ", out);
      json_string(out, qualified);
      free(qualified);
    }

    fputs("]\n", out);
    fprintf(out, "    }%s\n", i + 1 < slow_count ? "," : "");
  }

  fputs("  ],\n", out);
  fprintf(out, "  ");
  json_key(out, "timeouts");
  fputs("[", out);

  bool first = true;

  for (size_t i = 0; i < report->sample_count; i++)
  {
    if (strcmp(report->samples[i].status, STATUS_TIMEOUT) != 0)
      continue;

    if (!first)
      fputs(", ", out);
    first = false;
    json_string(out, report->samples[i].path);
  }

  fputs("],\n", out);
  fprintf(out, "  ");
  json_key(out, "memory_limit_samples");
  fputs("[", out);

  first = true;

  for (size_t i = 0; i < report->sample_count; i++)
  {
    if (strcmp(report->samples[i].status, STATUS_MEMORY_LIMIT) != 0)
      continue;

    if (!first)
      fputs(", ", out);
    first = false;
    json_string(out, report->samples[i].path);
  }

  fputs("],\n", out);
  fprintf(out, "  ");
  json_key(out, "errors");
  fputs("[", out);

  first = true;

  for (size_t i = 0; i < report->sample_count; i++)
  {
    if (strcmp(report->samples[i].status, STATUS_ERROR) != 0)
      continue;

    if (!first)
      fputs(", ", out);
    first = false;
    fprintf(out, "{\"path\": ");
    json_string(out, report->samples[i].path);
    fprintf(out, ", \"error_code\": %d}", report->samples[i].error_code);
  }

  fputs("]\n", out);
  fputs("}\n", out);

  free(rule_order);
  free(string_order);
  free(sample_order);
  free_groups(tags, tag_count);
  free_groups(authors, author_count);
  free_groups(severities, severity_count);
}

int main(int argc, const char** argv)
{
  YR_RULES* rules = NULL;
  REPORT report;
  PATH_LIST samples = {0};
  char* compile_error = NULL;
  uint64_t memory_limit = 0;
  FILE* output = stdout;
  FILE* folded = NULL;
  int result = EXIT_FAILURE;

  argc = args_parse(options, argc, argv);

  if (show_version)
  {
    printf("%s\n", YR_VERSION);
    return EXIT_SUCCESS;
  }

  if (show_help)
  {
    printf(
        "YARA %s performance analyzer.\n"
        "%s\n\n"
        "The JSON report is written to stdout unless --output is used.\n"
        "The folded stacks can be rendered with:\n"
        "  flamegraph.pl yara-perf.folded > yara-perf.svg\n\n",
        YR_VERSION,
        USAGE_STRING);

    args_print_usage(options, 46);
    return EXIT_SUCCESS;
  }

  if (argc != 2)
  {
    fprintf(stderr, "%s\n\nTry `--help` for more options\n", USAGE_STRING);
    return EXIT_FAILURE;
  }

  if (timeout_seconds < 0)
  {
    fprintf(stderr, "yara-perf: timeout must be zero or positive\n");
    return EXIT_FAILURE;
  }

  if (timeout_seconds > INT_MAX)
  {
    fprintf(stderr, "yara-perf: timeout is too large\n");
    return EXIT_FAILURE;
  }

  if (memory_limit_arg != NULL && !parse_size(memory_limit_arg, &memory_limit))
  {
    fprintf(stderr, "yara-perf: invalid memory limit: %s\n", memory_limit_arg);
    return EXIT_FAILURE;
  }

  if (folded_path == NULL)
    folded_path = "yara-perf.folded";

  if (strcmp(folded_path, "-") == 0)
  {
    fprintf(stderr, "yara-perf: --folded=- is not supported\n");
    return EXIT_FAILURE;
  }

  if (output_path != NULL && strcmp(output_path, "-") != 0 &&
      strcmp(output_path, folded_path) == 0)
  {
    fprintf(
        stderr,
        "yara-perf: --output and --folded must use different files\n");
    return EXIT_FAILURE;
  }

  if (yr_initialize() != ERROR_SUCCESS)
  {
    fprintf(stderr, "yara-perf: YARA initialization failed\n");
    goto _exit;
  }

  if (!compile_rules(argv[0], &rules, &compile_error))
  {
    fprintf(stderr, "yara-perf: %s\n", compile_error);
    free(compile_error);
    goto _exit;
  }

  if (!collect_paths(argv[1], false, 0, &samples))
    goto _exit;

  path_list_sort(&samples);

  if (output_path != NULL && strcmp(output_path, "-") != 0)
  {
    output = fopen(output_path, "w");

    if (output == NULL)
    {
      fprintf(
          stderr,
          "yara-perf: can't open output file %s: %s\n",
          output_path,
          strerror(errno));
      goto _exit;
    }
  }

  folded = fopen(folded_path, "w");

  if (folded == NULL)
  {
    fprintf(
        stderr,
        "yara-perf: can't open folded file %s: %s\n",
        folded_path,
        strerror(errno));
    goto _exit;
  }

  if (output_path != NULL && strcmp(output_path, "-") != 0)
    path_list_remove_file(&samples, output_path);

  path_list_remove_file(&samples, folded_path);

  if (samples.count == 0)
  {
    fprintf(stderr, "yara-perf: no samples found in %s\n", argv[1]);
    goto _exit;
  }

  if (!quiet)
  {
    fprintf(
        stderr,
        "yara-perf: scanning %zu sample(s) with %u rule(s) and %u string(s)\n",
        samples.count,
        rules->num_rules,
        rules->num_strings);
  }

  report_init(&report, rules);

  for (size_t i = 0; i < samples.count; i++)
  {
    if (!quiet)
    {
      fprintf(
          stderr, "yara-perf: [%zu/%zu] %s\n", i + 1, samples.count, samples.items[i]);
    }

    scan_sample(&report, samples.items[i], memory_limit, folded);
  }

  write_report(output, &report, argv[0], argv[1], memory_limit);

  if (output != stdout)
  {
    fclose(output);
    output = stdout;
  }
  else
    fflush(output);

  fclose(folded);
  folded = NULL;

  report_destroy(&report);
  result = EXIT_SUCCESS;

_exit:
  if (folded != NULL)
    fclose(folded);

  if (output != stdout)
    fclose(output);

  if (rules != NULL)
    yr_rules_destroy(rules);

  path_list_destroy(&samples);

  yr_finalize();
  args_free(options);

  return result;
}

#else

#include <stdio.h>

int main(int argc, const char** argv)
{
  (void) argc;
  (void) argv;
  fprintf(stderr, "yara-perf is currently supported only on POSIX systems\n");
  return 1;
}

#endif
