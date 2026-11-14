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

// Benchmark comparing the default fiber-based regexp engine against the DFA
// engine on long inputs. The DFA does a constant amount of work per input
// byte, while the fiber engine's cost grows with the number of live threads,
// which is what makes backtracking-heavy patterns expensive.
//
// This is a developer tool rather than a pass/fail test, so it is not added to
// the automake check_PROGRAMS list. Build it with:
//
//   make bench-re-dfa
//
// and run the resulting ./bench-re-dfa binary.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <yara.h>

#define BENCH_BUFFER_SIZE (4 * 1024)
#define BENCH_ITERATIONS 2

typedef struct _BENCH_PATTERN
{
  const char* regexp;
  const char* description;

} BENCH_PATTERN;

// Patterns chosen to stress the fiber engine: nested and adjacent quantifiers
// keep many threads alive simultaneously, which is the worst case for
// backtracking-style simulation.
static const BENCH_PATTERN patterns[] = {
    { "a+b+c+d+e+", "chain of plus quantifiers" },
    { "[ab]*c[ab]*d", "bounded character classes" },
    { "(foo|bar|baz)+qux", "alternation with quantifier" },
    { "(a|b)+c", "alternation with quantifier" },
    { "a*a*a*b", "adjacent star quantifiers" },
    { "(ab|a)*c", "ambiguous nested group" },
    { "(a|b|c|d)+e", "wide alternation" },
};

static double now_seconds(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);

  return (double) ts.tv_sec + (double) ts.tv_nsec / 1000000000.0;
}

static int counting_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  (void) context;
  (void) message_data;

  if (message == CALLBACK_MSG_RULE_MATCHING)
    (*(int*) user_data)++;

  return CALLBACK_CONTINUE;
}

// Fills "buffer" with a repetitive input that mostly fails to match, forcing
// both engines to explore every alternative before giving up at each
// position. A trailing 'b' occasionally completes a match.
static void build_worst_case_buffer(char* buffer, size_t size)
{
  for (size_t i = 0; i < size; i++)
  {
    buffer[i] = (i % 1024 == 1023) ? 'b' : 'a';
  }

  buffer[size - 1] = '\0';
}

static double run_once(
    const char* regexp,
    const char* buffer,
    bool enable_dfa,
    int* matches)
{
  char rule[256];
  YR_RULES* rules;
  YR_COMPILER* compiler;

  snprintf(
      rule,
      sizeof(rule),
      "rule bench { strings: $a = /%s/ condition: $a }",
      regexp);

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    fprintf(stderr, "compiler creation failed\n");
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_add_string(compiler, rule, NULL) != 0)
  {
    fprintf(stderr, "failed to compile rule: %s\n", rule);
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_compiler_get_rules failed\n");
    exit(EXIT_FAILURE);
  }

  yr_compiler_destroy(compiler);
  yr_set_configuration_uint32(YR_CONFIG_DFA_REGEXP, enable_dfa ? 1 : 0);

  *matches = 0;

  double start = now_seconds();

  int result = yr_rules_scan_mem(
      rules,
      (const uint8_t*) buffer,
      BENCH_BUFFER_SIZE,
      0,
      counting_callback,
      matches,
      0);

  double elapsed = now_seconds() - start;

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "scan failed with error %d\n", result);
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);
  yr_set_configuration_uint32(YR_CONFIG_DFA_REGEXP, 0);

  return elapsed;
}

int main(void)
{
  setvbuf(stdout, NULL, _IOLBF, 0);

  if (yr_initialize() != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_initialize failed\n");
    return EXIT_FAILURE;
  }

  char* buffer = (char*) malloc(BENCH_BUFFER_SIZE);

  if (buffer == NULL)
  {
    fprintf(stderr, "out of memory\n");
    return EXIT_FAILURE;
  }

  build_worst_case_buffer(buffer, BENCH_BUFFER_SIZE);

  printf(
      "Scanning %d KB input, best of %d runs per engine.\n\n",
      BENCH_BUFFER_SIZE / 1024,
      BENCH_ITERATIONS);
  printf(
      "%-28s %12s %12s %10s\n",
      "pattern",
      "NFA MB/s",
      "DFA MB/s",
      "speedup");
  printf(
      "--------------------------------------------------------------------\n");

  size_t pattern_count =
      sizeof(patterns) / sizeof(patterns[0]);

  for (size_t p = 0; p < pattern_count; p++)
  {
    double best_nfa = 1e30;
    double best_dfa = 1e30;
    int nfa_matches = 0;
    int dfa_matches = 0;

    for (int i = 0; i < BENCH_ITERATIONS; i++)
    {
      double elapsed = run_once(
          patterns[p].regexp, buffer, false, &nfa_matches);

      if (elapsed < best_nfa)
        best_nfa = elapsed;

      elapsed = run_once(
          patterns[p].regexp, buffer, true, &dfa_matches);

      if (elapsed < best_dfa)
        best_dfa = elapsed;
    }

    double mb = (double) BENCH_BUFFER_SIZE / (1024.0 * 1024.0);
    double nfa_throughput = mb / best_nfa;
    double dfa_throughput = mb / best_dfa;
    double speedup = dfa_throughput / nfa_throughput;

    printf(
        "%-28s %12.2f %12.2f %9.2fx (%s, matches nfa=%d dfa=%d)\n",
        patterns[p].regexp,
        nfa_throughput,
        dfa_throughput,
        speedup,
        patterns[p].description,
        nfa_matches,
        dfa_matches);

    if (nfa_matches != dfa_matches)
    {
      fprintf(
          stderr,
          "WARNING: match count mismatch for %s\n",
          patterns[p].regexp);
    }
  }

  free(buffer);
  yr_finalize();

  return EXIT_SUCCESS;
}
