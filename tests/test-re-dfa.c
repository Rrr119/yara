/*
Copyright (c) 2024. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.
*/

#include <stdio.h>
#include <string.h>
#include <yara.h>

#include "util.h"

// A single recorded string match: its offset within the scanned buffer and its
// length in bytes.
typedef struct _DFA_TEST_MATCH
{
  int64_t offset;
  int64_t length;

} DFA_TEST_MATCH;

typedef struct _DFA_TEST_CTX
{
  DFA_TEST_MATCH matches[4096];
  int count;
  int console_logs;

} DFA_TEST_CTX;

// Scan callback that records every individual string match (not just the rule
// hit) and counts console-log messages, which the engine uses to announce DFA
// fallbacks.
static int dfa_test_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  DFA_TEST_CTX* ctx = (DFA_TEST_CTX*) user_data;

  if (message == CALLBACK_MSG_CONSOLE_LOG)
  {
    ctx->console_logs++;
    return CALLBACK_CONTINUE;
  }

  if (message != CALLBACK_MSG_RULE_MATCHING)
    return CALLBACK_CONTINUE;

  YR_RULE* rule = (YR_RULE*) message_data;
  YR_STRING* string;

  yr_rule_strings_foreach(rule, string)
  {
    YR_MATCH* match;

    yr_string_matches_foreach(context, string, match)
    {
      if (ctx->count < (int) (sizeof(ctx->matches) / sizeof(ctx->matches[0])))
      {
        ctx->matches[ctx->count].offset = match->offset;
        ctx->matches[ctx->count].length = match->match_length;
        ctx->count++;
      }
    }
  }

  return CALLBACK_CONTINUE;
}

// Compiles "rule", scans "buffer" with the DFA engine enabled (or disabled)
// and fills "ctx" with the reported matches.
static void run_scan(
    const char* rule,
    const char* buffer,
    bool enable_dfa,
    DFA_TEST_CTX* ctx)
{
  YR_RULES* rules;

  memset(ctx, 0, sizeof(*ctx));

  assert_true_expr(compile_rule((char*) rule, &rules) == ERROR_SUCCESS);

  yr_set_configuration_uint32(YR_CONFIG_DFA_REGEXP, enable_dfa ? 1 : 0);

  int result = yr_rules_scan_mem(
      rules,
      (const uint8_t*) buffer,
      strlen(buffer),
      SCAN_FLAGS_NO_TRYCATCH,
      dfa_test_callback,
      ctx,
      0);

  assert_true_expr(result == ERROR_SUCCESS);

  yr_rules_destroy(rules);

  // Restore the default so later tests run with the original engine.
  yr_set_configuration_uint32(YR_CONFIG_DFA_REGEXP, 0);
}

// Runs the same rule and buffer through both engines and asserts that they
// produce the exact same sequence of (offset, length) matches.
static void assert_engines_agree(const char* rule, const char* buffer)
{
  DFA_TEST_CTX nfa;
  DFA_TEST_CTX dfa;

  run_scan(rule, buffer, false, &nfa);
  run_scan(rule, buffer, true, &dfa);

  if (nfa.count != dfa.count)
  {
    fprintf(
        stderr,
        "%s:%d: match count differs for %s: nfa=%d dfa=%d\n",
        __FILE__,
        __LINE__,
        rule,
        nfa.count,
        dfa.count);
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < nfa.count; i++)
  {
    if (nfa.matches[i].offset != dfa.matches[i].offset ||
        nfa.matches[i].length != dfa.matches[i].length)
    {
      fprintf(
          stderr,
          "%s:%d: match %d differs: nfa=(%lld,%lld) dfa=(%lld,%lld)\n",
          __FILE__,
          __LINE__,
          i,
          (long long) nfa.matches[i].offset,
          (long long) nfa.matches[i].length,
          (long long) dfa.matches[i].offset,
          (long long) dfa.matches[i].length);
      exit(EXIT_FAILURE);
    }
  }
}

// Empty matches: patterns that can match zero characters must report a
// zero-length match at every position, exactly like the fiber engine.
static void test_empty_matches(void)
{
  const char* rule =
      "rule test { strings: $a = /a*/ condition: $a }";

  DFA_TEST_CTX dfa;

  run_scan(rule, "baab", true, &dfa);

  // /a*/ reports empty matches at positions 0 and 3 plus "aa" and "a".
  int empty_matches = 0;

  for (int i = 0; i < dfa.count; i++)
  {
    if (dfa.matches[i].length == 0)
      empty_matches++;
  }

  assert_true_expr(empty_matches == 2);

  assert_engines_agree(
      "rule test { strings: $a = /a?/ condition: $a }",
      "baab");
  assert_engines_agree(
      "rule test { strings: $a = /x*/ condition: $a }",
      "abc");
}

// Overlapping matches: every starting position that can match is reported,
// including overlapping greedy matches of different lengths.
static void test_overlapping_matches(void)
{
  DFA_TEST_CTX dfa;

  run_scan(
      "rule test { strings: $a = /a+/ condition: $a }",
      "aaa",
      true,
      &dfa);

  // /a+/ over "aaa" yields three overlapping matches: lengths 3, 2 and 1.
  assert_true_expr(dfa.count == 3);
  assert_true_expr(dfa.matches[0].length == 3);
  assert_true_expr(dfa.matches[1].length == 2);
  assert_true_expr(dfa.matches[2].length == 1);

  assert_engines_agree(
      "rule test { strings: $a = /a{2,3}/ condition: $a }",
      "aaaaa");
  assert_engines_agree(
      "rule test { strings: $a = /(ab|a)b/ condition: $a }",
      "ab abb");
}

// Multi-line inputs: anchors, dot semantics and the dot-all modifier must
// behave identically to the fiber engine across newlines.
static void test_multiline(void)
{
  const char* input = "ab\nab\nac";

  assert_engines_agree(
      "rule test { strings: $a = /^ab/ condition: $a }",
      input);
  assert_engines_agree(
      "rule test { strings: $a = /ab$/ condition: $a }",
      input);
  assert_engines_agree(
      "rule test { strings: $a = /a.b/ condition: $a }",
      input);
  assert_engines_agree(
      "rule test { strings: $a = /a.b/s condition: $a }",
      input);
  assert_engines_agree(
      "rule test { strings: $a = /a.*b/s condition: $a }",
      input);
}

// Anchors and word boundaries at buffer edges and between words.
static void test_anchors_and_boundaries(void)
{
  assert_engines_agree(
      "rule test { strings: $a = /\\bfoo\\b/ condition: $a }",
      "foo .foo. foobar foo");
  assert_engines_agree(
      "rule test { strings: $a = /\\Bmid\\B/ condition: $a }",
      "amidships");
  assert_engines_agree(
      "rule test { strings: $a = /^only$/ condition: $a }",
      "only");
  assert_engines_agree(
      "rule test { strings: $a = /^only$/ condition: $a }",
      "onlyx");
}

// Case-insensitive and character-class matching.
static void test_nocase_and_classes(void)
{
  assert_engines_agree(
      "rule test { strings: $a = /abc/i condition: $a }",
      "AbC abc ABC");
  assert_engines_agree(
      "rule test { strings: $a = /[A-Z0-9_]+/ condition: $a }",
      "Hello World 123 _x");
  assert_engines_agree(
      "rule test { strings: $a = /[^aeiou]+/ condition: $a }",
      "rhythm and blues");
  assert_engines_agree(
      "rule test { strings: $a = /\\d+\\.\\d+/ condition: $a }",
      "v1.23 and 42.0");
}

// A hex string uses masked-literal bytecode that the DFA cannot represent.
// With the DFA enabled the scan must still succeed by falling back, and it
// must announce the fallback through a console-log message.
static void test_unsupported_falls_back(void)
{
  const char* rule =
      "rule test { strings: $h = { 41 ?? 43 } condition: $h }";

  DFA_TEST_CTX dfa;
  DFA_TEST_CTX nfa;

  run_scan(rule, "AxC", true, &dfa);
  run_scan(rule, "AxC", false, &nfa);

  assert_true_expr(dfa.count == nfa.count);
  assert_true_expr(dfa.console_logs > 0);
}

// The default configuration keeps the DFA disabled, so no fallback message is
// emitted and the behavior is unchanged.
static void test_default_engine_unchanged(void)
{
  const char* rule =
      "rule test { strings: $a = /a+/ condition: $a }";

  DFA_TEST_CTX ctx;

  run_scan(rule, "aaa", false, &ctx);

  assert_true_expr(ctx.console_logs == 0);
  assert_true_expr(ctx.count == 3);
}

int main(int argc, char** argv)
{
  init_top_srcdir();

  int result = yr_initialize();

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_initialize failed: %d\n", result);
    return EXIT_FAILURE;
  }

  test_empty_matches();
  test_overlapping_matches();
  test_multiline();
  test_anchors_and_boundaries();
  test_nocase_and_classes();
  test_unsupported_falls_back();
  test_default_engine_unchanged();

  yr_finalize();

  printf("test-re-dfa: all tests passed\n");

  (void) argc;
  (void) argv;

  return EXIT_SUCCESS;
}
