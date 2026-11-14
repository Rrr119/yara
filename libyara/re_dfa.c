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

/*

This module implements an alternative regular-expression engine based on a
lazily-constructed deterministic finite automaton (DFA), in the spirit of the
approach described by Russ Cox in https://swtch.com/~rsc/regexp/regexp3.html.

YARA's default engine (see re.c) simulates a Thompson NFA with a pool of
"fibers". Every input byte requires cloning, sorting and de-duplicating
fibers, which makes scans of long inputs with backtracking-heavy patterns
expensive. A DFA performs a fixed amount of work per input byte: one table
lookup, regardless of how complex the pattern is.

The DFA is built directly from the bytecode emitted by yr_re_ast_emit_code(),
so both engines share exactly the same parser, AST and code generator. A DFA
state is the set of NFA configurations reachable through epsilon transitions
(SPLIT, JUMP, REPEAT, anchors and word boundaries). Transitions between DFA
states are computed on demand and memoized.

Constructs that can't be expressed with this machinery (the masked literals
used by hex strings and the REPEAT_ANY operator) cause yr_re_dfa_is_supported()
to reject the bytecode up-front, and the caller falls back to the original
engine.

*/

#include <assert.h>
#include <string.h>

#include <yara/error.h>
#include <yara/globals.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/re.h>
#include <yara/re_dfa.h>
#include <yara/strutils.h>
#include <yara/unaligned.h>

// Cap on the number of DFA states cached for a single regular expression.
// When the cap is reached the engine gives up and the caller retries with the
// fiber-based engine. This keeps pathological patterns from exhausting memory.
#ifndef YR_RE_DFA_MAX_STATES
#define YR_RE_DFA_MAX_STATES 4096
#endif

// Cap on the number of distinct NFA configurations inside a single DFA state.
#ifndef YR_RE_DFA_MAX_CONFIGS
#define YR_RE_DFA_MAX_CONFIGS 2048
#endif

// The fiber engine allows up to RE_MAX_STACK nested repetitions, but storing
// such a stack in every configuration would make DFA states prohibitively
// large. Patterns nesting repetitions deeper than this cap simply fall back to
// the fiber engine.
#ifndef YR_RE_DFA_MAX_REPEAT_DEPTH
#define YR_RE_DFA_MAX_REPEAT_DEPTH 64
#endif

// Per-closure cap on the number of distinct split IDs visited along one
// expansion path. Equivalent to the splits_executed array in the fiber engine
// but bounded; hitting the cap triggers a fallback.
#ifndef YR_RE_DFA_MAX_SPLIT_PATH
#define YR_RE_DFA_MAX_SPLIT_PATH 64
#endif

// Mirrors the packed YR_RE_DFA_REPEAT_ARGS structure embedded in the bytecode by
// re.c. It is not exposed through any public header, so the DFA engine keeps
// its own layout-identical copy.
#pragma pack(push)
#pragma pack(1)
typedef struct _YR_RE_DFA_REPEAT_ARGS
{
  uint16_t min;
  uint16_t max;
  int32_t offset;

} YR_RE_DFA_REPEAT_ARGS;
#pragma pack(pop)

// An NFA configuration: an instruction pointer together with the state of the
// repeat-counter stack used by the REPEAT_START/REPEAT_END bytecodes and the
// standalone repeat counter (rc) used by REPEAT_ANY. REPEAT_ANY is rejected by
// yr_re_dfa_is_supported(), so rc is always -1 here, but the field is kept to
// make the structure self describing.
typedef struct _YR_RE_DFA_CONFIG
{
  const uint8_t* ip;
  int32_t rc;
  int32_t sp;
  uint16_t stack[YR_RE_DFA_MAX_REPEAT_DEPTH];

} YR_RE_DFA_CONFIG;

// Boundary conditions at the input position where a DFA state is evaluated.
// Anchors and word boundaries depend on the position in the input, so they
// can't be decided while building a position-independent closure. Instead the
// closure keeps configurations sitting on anchor instructions, and the state
// records which boundary conditions are currently true.
typedef struct _YR_RE_DFA_BOUNDARIES
{
  bool at_start;
  bool at_end;

  // Word-character status of the byte immediately before and at the current
  // position. A position outside the buffer is treated as a non-word
  // character, matching _yr_re_fiber_sync.
  bool prev_is_word;
  bool cur_is_word;

} YR_RE_DFA_BOUNDARIES;

typedef struct _YR_RE_DFA_STATE YR_RE_DFA_STATE;
typedef struct _YR_RE_DFA_CLOSURE_ITEM YR_RE_DFA_CLOSURE_ITEM;

struct _YR_RE_DFA_STATE
{
  // Sorted array of NFA configurations that define this DFA state.
  YR_RE_DFA_CONFIG* configs;
  int num_configs;

  // Boundary conditions at the position represented by this state. Anchors
  // are resolved while building the state's closure, so states reached at
  // positions with different boundary conditions are kept distinct.
  YR_RE_DFA_BOUNDARIES boundaries;

  // Transition table, one entry per possible input byte. A NULL value means
  // that the transition has not been computed yet; the dead_state member
  // represents transitions that no configuration accepts.
  YR_RE_DFA_STATE* next[256];

  // Hash-table linkage, keyed on the configuration set.
  YR_RE_DFA_STATE* hash_next;

  // Linked list of every state owned by the automaton, used for cleanup.
  YR_RE_DFA_STATE* list_next;
};

struct YR_RE_DFA
{
  const uint8_t* code;
  int flags;

  // True when the bytecode contains any anchor or word boundary. Transitions
  // of such patterns are position dependent, so they are recomputed per byte
  // instead of memoized in the per-state transition table.
  bool contains_anchor;

  // Start states for the 16 possible boundary-flag combinations.
  YR_RE_DFA_STATE* start_states[16];
  // Shared state representing the empty configuration set. It is allocated
  // once and used to mark transitions that lead nowhere without confusing them
  // with not-yet-computed (NULL) transitions.
  YR_RE_DFA_STATE* dead_state;
  YR_RE_DFA_STATE* states_head;
  int num_states;

  // Open-addressing hash table of states.
  YR_RE_DFA_STATE** buckets;
  int num_buckets;

  // Reusable scratch buffers for closure expansion. They are owned by the DFA
  // and grown lazily, keeping multi-megabyte work arrays off the C stack.
  YR_RE_DFA_CONFIG* work_configs;
  YR_RE_DFA_CLOSURE_ITEM* work_items;
  int work_capacity;

  struct YR_RE_DFA* next;

};

#define CHAR_IN_CLASS(cls, chr) ((cls)[(chr) / 8] & 1 << ((chr) % 8))

static bool _yr_re_dfa_char_in_class(
    const RE_CLASS* re_class,
    uint8_t chr,
    int case_insensitive)
{
  int result = CHAR_IN_CLASS(re_class->bitmap, chr);

  if (case_insensitive)
    result |= CHAR_IN_CLASS(re_class->bitmap, yr_altercase[chr]);

  if (re_class->negated)
    result = !result;

  return result;
}

static bool _yr_re_dfa_is_word_char(const uint8_t* input)
{
  return yr_isalnum(input) || (*input) == '_';
}

// Returns true if the byte at the given instruction pointer is accepted by the
// consuming instruction the configuration is sitting on. Zero-width
// instructions (splits, jumps, repeats, anchors) are handled by the closure
// routine instead.
static bool _yr_re_dfa_byte_matches(
    const uint8_t* ip,
    uint8_t chr,
    int flags)
{
  switch (*ip)
  {
  case RE_OPCODE_ANY:
    return (flags & RE_FLAGS_DOT_ALL) || (chr != 0x0A);

  case RE_OPCODE_LITERAL:
    if (flags & RE_FLAGS_NO_CASE)
      return yr_lowercase[chr] == yr_lowercase[*(ip + 1)];
    return chr == *(ip + 1);

  case RE_OPCODE_NOT_LITERAL:
    return chr != *(ip + 1);

  case RE_OPCODE_CLASS:
    return _yr_re_dfa_char_in_class(
        (const RE_CLASS*) (ip + 1), chr, flags & RE_FLAGS_NO_CASE);

  case RE_OPCODE_WORD_CHAR:
    return _yr_re_dfa_is_word_char(&chr);

  case RE_OPCODE_NON_WORD_CHAR:
    return !_yr_re_dfa_is_word_char(&chr);

  case RE_OPCODE_SPACE:
  case RE_OPCODE_NON_SPACE:
  {
    bool match;

    switch (chr)
    {
    case ' ':
    case '\t':
    case '\r':
    case '\n':
    case '\v':
    case '\f':
      match = true;
      break;
    default:
      match = false;
    }

    if (*ip == RE_OPCODE_NON_SPACE)
      match = !match;

    return match;
  }

  case RE_OPCODE_DIGIT:
    return isdigit(chr);

  case RE_OPCODE_NON_DIGIT:
    return !isdigit(chr);

  default:
    return false;
  }
}

// Size in bytes of the instruction at ip, including its arguments. Consuming
// instructions and control-flow opcodes are both covered so that the bytecode
// can be walked linearly by yr_re_dfa_is_supported().
static int _yr_re_dfa_instr_size(const uint8_t* ip)
{
  switch (*ip)
  {
  case RE_OPCODE_LITERAL:
  case RE_OPCODE_NOT_LITERAL:
    return 2;

  case RE_OPCODE_MASKED_LITERAL:
  case RE_OPCODE_MASKED_NOT_LITERAL:
    return 3;

  case RE_OPCODE_CLASS:
    return 1 + (int) sizeof(RE_CLASS);

  // SPLIT_A/SPLIT_B: opcode + split id (1 byte) + int16 offset.
  case RE_OPCODE_SPLIT_A:
  case RE_OPCODE_SPLIT_B:
    return 1 + (int) sizeof(uint8_t) + (int) sizeof(int16_t);

  // JUMP: opcode + int16 offset.
  case RE_OPCODE_JUMP:
    return 1 + (int) sizeof(int16_t);

  // REPEAT_START/REPEAT_END: opcode + RE_REPEAT_ARGS.
  case RE_OPCODE_REPEAT_START_GREEDY:
  case RE_OPCODE_REPEAT_START_UNGREEDY:
  case RE_OPCODE_REPEAT_END_GREEDY:
  case RE_OPCODE_REPEAT_END_UNGREEDY:
    return 1 + (int) sizeof(YR_RE_DFA_REPEAT_ARGS);

  // REPEAT_ANY: opcode + RE_REPEAT_ANY_ARGS (two uint16 values).
  case RE_OPCODE_REPEAT_ANY_GREEDY:
  case RE_OPCODE_REPEAT_ANY_UNGREEDY:
    return 1 + 2 * (int) sizeof(uint16_t);

  default:
    return 1;
  }
}

YR_RE_DFA_RESULT yr_re_dfa_is_supported(const uint8_t* code)
{
  const uint8_t* ip = code;

  while (true)
  {
    switch (*ip)
    {
    // Masked literals and the "any" repetition are only emitted for hex
    // strings, whose semantics (nibble masks) can't be represented on the
    // byte-oriented DFA alphabet.
    case RE_OPCODE_MASKED_LITERAL:
    case RE_OPCODE_MASKED_NOT_LITERAL:
    case RE_OPCODE_REPEAT_ANY_GREEDY:
    case RE_OPCODE_REPEAT_ANY_UNGREEDY:
      return YR_RE_DFA_FALLBACK;

    case RE_OPCODE_MATCH:
      return YR_RE_DFA_OK;

    default:
      ip += _yr_re_dfa_instr_size(ip);
    }
  }
}

// Scans the bytecode for anchor or word-boundary opcodes. Patterns containing
// them produce position-dependent transitions that the memoized transition
// table can't represent safely.
static bool _yr_re_dfa_code_has_anchor(const uint8_t* code)
{
  const uint8_t* ip = code;

  while (*ip != RE_OPCODE_MATCH)
  {
    switch (*ip)
    {
    case RE_OPCODE_MATCH_AT_START:
    case RE_OPCODE_MATCH_AT_END:
    case RE_OPCODE_WORD_BOUNDARY:
    case RE_OPCODE_NON_WORD_BOUNDARY:
      return true;

    default:
      ip += _yr_re_dfa_instr_size(ip);
    }
  }

  return false;
}

// A work item extends an NFA configuration with the bookkeeping required
// while expanding its epsilon closure. "splits" records the split IDs already
// visited along the current expansion path; it mirrors the splits_executed
// array used by _yr_re_fiber_sync and prevents infinite loops on patterns like
// (a*)*. It is not part of the configuration identity.
typedef struct _YR_RE_DFA_CLOSURE_ITEM
{
  YR_RE_DFA_CONFIG config;
  uint8_t splits[YR_RE_DFA_MAX_SPLIT_PATH];
  int num_splits;

} YR_RE_DFA_CLOSURE_ITEM;

static bool _yr_re_dfa_configs_equal(
    const YR_RE_DFA_CONFIG* a,
    const YR_RE_DFA_CONFIG* b)
{
  if (a->ip != b->ip || a->rc != b->rc || a->sp != b->sp)
    return false;

  for (int32_t i = 0; i <= a->sp; i++)
  {
    if (a->stack[i] != b->stack[i])
      return false;
  }

  return true;
}

static int _yr_re_dfa_configs_compare(
    const YR_RE_DFA_CONFIG* a,
    const YR_RE_DFA_CONFIG* b)
{
  if (a->ip != b->ip)
    return a->ip < b->ip ? -1 : 1;

  if (a->sp != b->sp)
    return a->sp < b->sp ? -1 : 1;

  for (int32_t i = 0; i <= a->sp; i++)
  {
    if (a->stack[i] != b->stack[i])
      return a->stack[i] < b->stack[i] ? -1 : 1;
  }

  if (a->rc != b->rc)
    return a->rc < b->rc ? -1 : 1;

  return 0;
}

static int _yr_re_dfa_compare_config_arrays(
    const YR_RE_DFA_CONFIG* a,
    int na,
    const YR_RE_DFA_CONFIG* b,
    int nb)
{
  if (na != nb)
    return na < nb ? -1 : 1;

  for (int i = 0; i < na; i++)
  {
    int cmp = _yr_re_dfa_configs_compare(&a[i], &b[i]);

    if (cmp != 0)
      return cmp;
  }

  return 0;
}

// Sorts a configuration array and removes duplicates in place.
static void _yr_re_dfa_sort_dedup(
    YR_RE_DFA_CONFIG* configs,
    int* count)
{
  int n = *count;

  for (int i = 1; i < n; i++)
  {
    YR_RE_DFA_CONFIG key = configs[i];
    int j = i - 1;

    while (j >= 0 &&
           _yr_re_dfa_configs_compare(&configs[j], &key) > 0)
    {
      configs[j + 1] = configs[j];
      j--;
    }

    configs[j + 1] = key;
  }

  int out = 0;

  for (int i = 0; i < n; i++)
  {
    if (out == 0 ||
        !_yr_re_dfa_configs_equal(&configs[out - 1], &configs[i]))
    {
      configs[out++] = configs[i];
    }
  }

  *count = out;
}

static bool _yr_re_dfa_contains_config(
    const YR_RE_DFA_CONFIG* configs,
    int count,
    const YR_RE_DFA_CONFIG* config)
{
  for (int i = 0; i < count; i++)
  {
    if (_yr_re_dfa_configs_equal(&configs[i], config))
      return true;
  }

  return false;
}

static bool _yr_re_dfa_closure_contains_split(
    const YR_RE_DFA_CLOSURE_ITEM* item,
    uint8_t split_id)
{
  for (int i = 0; i < item->num_splits; i++)
  {
    if (item->splits[i] == split_id)
      return true;
  }

  return false;
}

// Evaluates a zero-width anchor or word-boundary instruction against the
// current input position. "pos" is the number of bytes consumed since
// Evaluates an anchor instruction against a set of boundary conditions.
static bool _yr_re_dfa_anchor_matches(
    uint8_t opcode,
    const YR_RE_DFA_BOUNDARIES* boundaries)
{
  switch (opcode)
  {
  case RE_OPCODE_MATCH_AT_START:
    return boundaries->at_start;

  case RE_OPCODE_MATCH_AT_END:
    return boundaries->at_end;

  case RE_OPCODE_WORD_BOUNDARY:
    return boundaries->prev_is_word != boundaries->cur_is_word;

  case RE_OPCODE_NON_WORD_BOUNDARY:
    return boundaries->prev_is_word == boundaries->cur_is_word;

  default:
    return true;
  }
}

static bool _yr_re_dfa_is_anchor_opcode(uint8_t opcode)
{
  switch (opcode)
  {
  case RE_OPCODE_MATCH_AT_START:
  case RE_OPCODE_MATCH_AT_END:
  case RE_OPCODE_WORD_BOUNDARY:
  case RE_OPCODE_NON_WORD_BOUNDARY:
    return true;
  default:
    return false;
  }
}

// A state accepts when it contains a RE_OPCODE_MATCH configuration. Anchors
// are resolved while the state's closure is built, so a configuration only
// reaches MATCH when every preceding assertion held at the right position.
static bool _yr_re_dfa_state_accepts(
    const YR_RE_DFA_STATE* state,
    const YR_RE_DFA_BOUNDARIES* boundaries)
{
  (void) boundaries;

  for (int i = 0; i < state->num_configs; i++)
  {
    if (*state->configs[i].ip == RE_OPCODE_MATCH)
      return true;
  }

  return false;
}

// Expands the epsilon closure of the configurations in "work", stopping at
// consuming instructions, anchors and RE_OPCODE_MATCH. The resulting
// configurations are appended to "out". Returns false when a resource limit is
// hit.
static bool _yr_re_dfa_expand_closure(
    YR_RE_DFA* dfa,
    int* work_count,
    int* out_count,
    const YR_RE_DFA_BOUNDARIES* boundaries)
{
  YR_RE_DFA_CLOSURE_ITEM* work = dfa->work_items;
  YR_RE_DFA_CONFIG* out = dfa->work_configs;

  while (*work_count > 0)
  {
    YR_RE_DFA_CLOSURE_ITEM item = work[--(*work_count)];
    const uint8_t* ip = item.config.ip;

    switch (*ip)
    {
    case RE_OPCODE_SPLIT_A:
    case RE_OPCODE_SPLIT_B:
    {
      uint8_t split_id = *(uint8_t*) (ip + 1);
      int16_t jmp_len = yr_unaligned_i16(ip + 1 + sizeof(uint8_t));

      if (_yr_re_dfa_closure_contains_split(&item, split_id))
        break;

      if (*work_count + 2 > dfa->work_capacity ||
          item.num_splits + 1 > YR_RE_DFA_MAX_SPLIT_PATH)
        return false;

      YR_RE_DFA_CLOSURE_ITEM branch_a = item;
      YR_RE_DFA_CLOSURE_ITEM branch_b = item;

      // Branch A continues at the next instruction, branch B jumps.
      branch_a.config.ip = ip + 1 + sizeof(uint8_t) + sizeof(int16_t);
      branch_b.config.ip = ip + jmp_len;

      if (*ip == RE_OPCODE_SPLIT_B)
      {
        YR_RE_DFA_CLOSURE_ITEM tmp = branch_a;
        branch_a = branch_b;
        branch_b = tmp;
      }

      branch_a.splits[branch_a.num_splits++] = split_id;
      branch_b.splits[branch_b.num_splits++] = split_id;

      work[(*work_count)++] = branch_a;
      work[(*work_count)++] = branch_b;
      break;
    }

    case RE_OPCODE_JUMP:
    {
      int16_t jmp_len = yr_unaligned_i16(ip + 1);
      item.config.ip = ip + jmp_len;

      if (*work_count + 1 > dfa->work_capacity)
        return false;

      work[(*work_count)++] = item;
      break;
    }

    case RE_OPCODE_REPEAT_START_GREEDY:
    case RE_OPCODE_REPEAT_START_UNGREEDY:
    {
      YR_RE_DFA_REPEAT_ARGS* args = (YR_RE_DFA_REPEAT_ARGS*) (ip + 1);

      if (item.config.sp >= YR_RE_DFA_MAX_REPEAT_DEPTH - 1)
        return false;

      if (args->min == 0)
      {
        if (*work_count + 2 > dfa->work_capacity)
          return false;

        YR_RE_DFA_CLOSURE_ITEM skip = item;

        skip.config.ip = ip + args->offset;
        work[(*work_count)++] = skip;
      }

      item.config.stack[++item.config.sp] = 0;
      item.config.ip += 1 + (int) sizeof(YR_RE_DFA_REPEAT_ARGS);
      work[(*work_count)++] = item;
      break;
    }

    case RE_OPCODE_REPEAT_END_GREEDY:
    case RE_OPCODE_REPEAT_END_UNGREEDY:
    {
      YR_RE_DFA_REPEAT_ARGS* args = (YR_RE_DFA_REPEAT_ARGS*) (ip + 1);

      if (item.config.sp < 0)
        return false;

      item.config.stack[item.config.sp]++;

      if (item.config.stack[item.config.sp] < args->min)
      {
        item.config.ip = ip + args->offset;

        if (*work_count + 1 > dfa->work_capacity)
          return false;

        work[(*work_count)++] = item;
        break;
      }

      if (item.config.stack[item.config.sp] < args->max)
      {
        if (*work_count + 2 > dfa->work_capacity)
          return false;

        YR_RE_DFA_CLOSURE_ITEM loop = item;

        loop.config.ip = ip + args->offset;
        work[(*work_count)++] = loop;
      }

      item.config.sp--;
      item.config.ip += 1 + (int) sizeof(YR_RE_DFA_REPEAT_ARGS);
      work[(*work_count)++] = item;
      break;
    }

    case RE_OPCODE_MATCH_AT_START:
    case RE_OPCODE_MATCH_AT_END:
    case RE_OPCODE_WORD_BOUNDARY:
    case RE_OPCODE_NON_WORD_BOUNDARY:
      // Reached through an epsilon path (JUMP/SPLIT). Evaluate the assertion
      // at the current position: expand past it when it holds, drop the
      // configuration otherwise.
      if (_yr_re_dfa_anchor_matches(*ip, boundaries))
      {
        item.config.ip = ip + 1;

        if (*work_count + 1 > dfa->work_capacity)
          return false;

        work[(*work_count)++] = item;
      }
      break;

    default:
      // Consuming instruction or RE_OPCODE_MATCH: the configuration settles
      // here and becomes part of the DFA state.
      if (*out_count >= dfa->work_capacity)
        return false;

      if (!_yr_re_dfa_contains_config(
              out, *out_count, &item.config))
      {
        out[(*out_count)++] = item.config;
      }
    }
  }

  return true;
}

static uint32_t _yr_re_dfa_hash_state(
    const YR_RE_DFA_CONFIG* configs,
    int count,
    const YR_RE_DFA_BOUNDARIES* boundaries)
{
  // FNV-1a over the raw configuration bytes plus the boundary flags.
  uint32_t hash = 2166136261u;
  const uint8_t* bytes = (const uint8_t*) configs;
  size_t len = (size_t) count * sizeof(YR_RE_DFA_CONFIG);

  for (size_t i = 0; i < len; i++)
  {
    hash ^= bytes[i];
    hash *= 16777619u;
  }

  hash ^= (uint8_t) boundaries->at_start;
  hash *= 16777619u;
  hash ^= (uint8_t) boundaries->at_end;
  hash *= 16777619u;
  hash ^= (uint8_t) boundaries->prev_is_word;
  hash *= 16777619u;
  hash ^= (uint8_t) boundaries->cur_is_word;
  hash *= 16777619u;

  return hash;
}

static bool _yr_re_dfa_state_equals(
    const YR_RE_DFA_STATE* state,
    const YR_RE_DFA_CONFIG* configs,
    int count,
    const YR_RE_DFA_BOUNDARIES* boundaries)
{
  if (state->boundaries.at_start != boundaries->at_start ||
      state->boundaries.at_end != boundaries->at_end ||
      state->boundaries.prev_is_word != boundaries->prev_is_word ||
      state->boundaries.cur_is_word != boundaries->cur_is_word)
  {
    return false;
  }

  return _yr_re_dfa_compare_config_arrays(
             state->configs,
             state->num_configs,
             configs,
             count) == 0;
}

static void _yr_re_dfa_state_free(YR_RE_DFA_STATE* state)
{
  yr_free(state->configs);
  yr_free(state);
}

// Allocates a state holding a copy of the given configurations. The caller
// decides whether it goes into the shared hash table or the temporary list.
static YR_RE_DFA_STATE* _yr_re_dfa_alloc_state(
    YR_RE_DFA* dfa,
    YR_RE_DFA_CONFIG* configs,
    int count,
    const YR_RE_DFA_BOUNDARIES* boundaries)
{
  (void) dfa;

  YR_RE_DFA_STATE* state =
      (YR_RE_DFA_STATE*) yr_malloc(sizeof(YR_RE_DFA_STATE));

  if (state == NULL)
    return NULL;

  state->configs = (YR_RE_DFA_CONFIG*) yr_malloc(
      (size_t) count * sizeof(YR_RE_DFA_CONFIG));

  if (state->configs == NULL)
  {
    yr_free(state);
    return NULL;
  }

  memcpy(state->configs, configs, (size_t) count * sizeof(YR_RE_DFA_CONFIG));
  state->num_configs = count;
  state->boundaries = *boundaries;

  state->hash_next = NULL;
  state->list_next = NULL;

  memset(state->next, 0, sizeof(state->next));

  return state;
}

// Looks up an existing state for (configs, boundaries) or creates a new one.
// On allocation failure or when the state cap is reached returns NULL.
static YR_RE_DFA_STATE* _yr_re_dfa_get_or_create_state(
    YR_RE_DFA* dfa,
    YR_RE_DFA_CONFIG* configs,
    int count,
    const YR_RE_DFA_BOUNDARIES* boundaries)
{
  uint32_t hash = _yr_re_dfa_hash_state(configs, count, boundaries);
  uint32_t bucket = hash % (uint32_t) dfa->num_buckets;
  YR_RE_DFA_STATE* state = dfa->buckets[bucket];

  while (state != NULL)
  {
    if (_yr_re_dfa_state_equals(state, configs, count, boundaries))
      return state;

    state = state->hash_next;
  }

  if (dfa->num_states >= YR_RE_DFA_MAX_STATES)
    return NULL;

  state = _yr_re_dfa_alloc_state(dfa, configs, count, boundaries);

  if (state == NULL)
    return NULL;

  state->hash_next = dfa->buckets[bucket];
  state->list_next = dfa->states_head;
  dfa->buckets[bucket] = state;
  dfa->states_head = state;
  dfa->num_states++;

  return state;
}

// Computes the destination state of "from" for a specific input byte. Returns
// YR_RE_DFA_OK and sets *to (possibly to NULL for a dead transition), or an
// error code when a resource limit is hit.
static YR_RE_DFA_RESULT _yr_re_dfa_compute_transition(
    YR_RE_DFA* dfa,
    YR_RE_DFA_STATE* from,
    uint8_t chr,
    const YR_RE_DFA_BOUNDARIES* boundaries,
    YR_RE_DFA_STATE** to)
{
  int settled_count = 0;
  int work_count = 0;
  *to = NULL;

  // Move every configuration sitting on a matching consuming instruction one
  // step forward and seed the closure work list with it.
  for (int i = 0; i < from->num_configs; i++)
  {
    const uint8_t* ip = from->configs[i].ip;

    if (*ip == RE_OPCODE_MATCH)
      continue;

    // Anchors are zero-width position assertions evaluated exactly at the
    // position where the configuration is parked. They never consume the
    // byte: when the assertion holds, advance past it (the closure expands
    // whatever follows); when it doesn't, the configuration dies here and is
    // dropped rather than deferred to a later position.
    if (_yr_re_dfa_is_anchor_opcode(*ip))
    {
      if (!_yr_re_dfa_anchor_matches(*ip, boundaries))
        continue;

      if (work_count >= dfa->work_capacity)
        return YR_RE_DFA_RESOURCE_LIMIT;

      YR_RE_DFA_CLOSURE_ITEM anchor_item;

      anchor_item.config = from->configs[i];
      anchor_item.num_splits = 0;
      anchor_item.config.ip = ip + 1;

      dfa->work_items[work_count++] = anchor_item;
      continue;
    }

    if (!_yr_re_dfa_byte_matches(ip, chr, dfa->flags))
      continue;

    if (work_count >= dfa->work_capacity)
      return YR_RE_DFA_RESOURCE_LIMIT;

    YR_RE_DFA_CLOSURE_ITEM item;

    item.config = from->configs[i];
    item.config.ip = ip + _yr_re_dfa_instr_size(ip);
    item.num_splits = 0;
    dfa->work_items[work_count++] = item;
  }

  if (!_yr_re_dfa_expand_closure(
          dfa, &work_count, &settled_count, boundaries))
    return YR_RE_DFA_RESOURCE_LIMIT;

  if (settled_count == 0)
    return YR_RE_DFA_OK;

  _yr_re_dfa_sort_dedup(dfa->work_configs, &settled_count);

  YR_RE_DFA_STATE* next = _yr_re_dfa_get_or_create_state(
      dfa, dfa->work_configs, settled_count, boundaries);

  if (next == NULL)
    return YR_RE_DFA_RESOURCE_LIMIT;

  *to = next;
  return YR_RE_DFA_OK;
}

static void _yr_re_dfa_free(YR_RE_DFA* dfa)
{
  YR_RE_DFA_STATE* state = dfa->states_head;

  while (state != NULL)
  {
    YR_RE_DFA_STATE* next = state->list_next;
    _yr_re_dfa_state_free(state);
    state = next;
  }

  yr_free(dfa->work_items);
  yr_free(dfa->work_configs);
  yr_free(dfa->buckets);
  yr_free(dfa);
}

// Encodes the four boundary flags into the start-state cache key.
static int _yr_re_dfa_boundary_key(const YR_RE_DFA_BOUNDARIES* boundaries)
{
  int key = 0;

  if (boundaries->at_start)
    key |= 1;
  if (boundaries->at_end)
    key |= 2;
  if (boundaries->prev_is_word)
    key |= 4;
  if (boundaries->cur_is_word)
    key |= 8;

  return key;
}

// Returns the start state for the given boundary conditions, building and
// caching it on first use. Only 16 boundary combinations exist, so the start
// states live in a small fixed array.
static YR_RE_DFA_RESULT _yr_re_dfa_get_start_state(
    YR_RE_DFA* dfa,
    const YR_RE_DFA_BOUNDARIES* boundaries,
    YR_RE_DFA_STATE** state)
{
  int key = _yr_re_dfa_boundary_key(boundaries);

  if (dfa->start_states[key] != NULL)
  {
    *state = dfa->start_states[key];
    return YR_RE_DFA_OK;
  }

  int settled_count = 0;
  int work_count = 0;

  YR_RE_DFA_CLOSURE_ITEM seed;

  memset(&seed, 0, sizeof(seed));
  seed.config.ip = dfa->code;
  seed.config.rc = -1;
  seed.config.sp = -1;
  dfa->work_items[work_count++] = seed;

  if (!_yr_re_dfa_expand_closure(
          dfa, &work_count, &settled_count, boundaries))
    return YR_RE_DFA_RESOURCE_LIMIT;

  _yr_re_dfa_sort_dedup(dfa->work_configs, &settled_count);

  YR_RE_DFA_STATE* start = _yr_re_dfa_get_or_create_state(
      dfa, dfa->work_configs, settled_count, boundaries);

  if (start == NULL)
    return YR_RE_DFA_RESOURCE_LIMIT;

  dfa->start_states[key] = start;
  *state = start;

  return YR_RE_DFA_OK;
}

static YR_RE_DFA_CACHE* _yr_re_dfa_get_cache(YR_SCAN_CONTEXT* context)
{
  return (YR_RE_DFA_CACHE*) &context->re_dfa_cache;
}

static YR_RE_DFA* _yr_re_dfa_cache_lookup(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code,
    int flags)
{
  YR_RE_DFA_CACHE* cache = _yr_re_dfa_get_cache(context);
  YR_RE_DFA* dfa = cache->head;

  while (dfa != NULL)
  {
    if (dfa->code == code && dfa->flags == flags)
      return dfa;

    dfa = dfa->next;
  }

  return NULL;
}

static YR_RE_DFA_RESULT _yr_re_dfa_cache_create(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code,
    int flags,
    YR_RE_DFA** result)
{
  YR_RE_DFA* dfa = (YR_RE_DFA*) yr_calloc(1, sizeof(YR_RE_DFA));

  if (dfa == NULL)
    return YR_RE_DFA_RESOURCE_LIMIT;

  // A load factor around 0.7 keeps the open-addressing lookup short.
  dfa->num_buckets = 64;
  dfa->buckets = (YR_RE_DFA_STATE**) yr_calloc(
      dfa->num_buckets, sizeof(YR_RE_DFA_STATE*));

  if (dfa->buckets == NULL)
  {
    yr_free(dfa);
    return YR_RE_DFA_RESOURCE_LIMIT;
  }

  dfa->work_capacity = YR_RE_DFA_MAX_CONFIGS;
  dfa->work_configs = (YR_RE_DFA_CONFIG*) yr_malloc(
      (size_t) dfa->work_capacity * sizeof(YR_RE_DFA_CONFIG));
  dfa->work_items = (YR_RE_DFA_CLOSURE_ITEM*) yr_malloc(
      (size_t) dfa->work_capacity * sizeof(YR_RE_DFA_CLOSURE_ITEM));

  if (dfa->work_configs == NULL || dfa->work_items == NULL)
  {
    yr_free(dfa->work_configs);
    yr_free(dfa->work_items);
    yr_free(dfa->buckets);
    yr_free(dfa);
    return YR_RE_DFA_RESOURCE_LIMIT;
  }

  dfa->code = code;
  dfa->flags = flags;
  dfa->contains_anchor = _yr_re_dfa_code_has_anchor(code);
  dfa->states_head = NULL;
  dfa->num_states = 0;

  YR_RE_DFA_CACHE* cache = _yr_re_dfa_get_cache(context);

  dfa->next = cache->head;
  cache->head = dfa;
  *result = dfa;

  return YR_RE_DFA_OK;
}

void yr_re_dfa_cache_destroy(YR_SCAN_CONTEXT* context)
{
  YR_RE_DFA_CACHE* cache = _yr_re_dfa_get_cache(context);
  YR_RE_DFA* dfa = cache->head;

  while (dfa != NULL)
  {
    YR_RE_DFA* next = dfa->next;
    _yr_re_dfa_free(dfa);
    dfa = next;
  }

  cache->head = NULL;
}

bool yr_re_dfa_mark_fallback_notified(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code)
{
  YR_RE_DFA_CACHE* cache = _yr_re_dfa_get_cache(context);

  for (int i = 0; i < cache->num_notified; i++)
  {
    if (cache->notified[i] == code)
      return false;
  }

  if (cache->num_notified <
      (int) (sizeof(cache->notified) / sizeof(cache->notified[0])))
  {
    cache->notified[cache->num_notified++] = code;
  }

  return true;
}

// Reports a match of "match_length" bytes starting at input_data, applying the
// same limit as the fiber engine (YR_RE_SCAN_LIMIT) and honoring the optional
// exhaustive callback.
static YR_RE_DFA_RESULT _yr_re_dfa_report_match(
    int match_length,
    int max_bytes_matched,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args,
    const uint8_t* input_data,
    int flags,
    int* matches)
{
  if (match_length > max_bytes_matched)
    return YR_RE_DFA_OK;

  if (*matches < 0 || match_length > *matches)
    *matches = match_length;

  if ((flags & RE_FLAGS_EXHAUSTIVE) && callback != NULL)
  {
    if (callback(input_data, match_length, flags, callback_args) !=
        ERROR_SUCCESS)
    {
      return YR_RE_DFA_RESOURCE_LIMIT;
    }
  }

  return YR_RE_DFA_OK;
}

// Creates the shared dead state: an empty, non-accepting state whose every
// transition points back at itself.
static YR_RE_DFA_RESULT _yr_re_dfa_build_dead_state(YR_RE_DFA* dfa)
{
  YR_RE_DFA_BOUNDARIES zero_boundaries = {0};
  YR_RE_DFA_CONFIG empty;

  memset(&empty, 0, sizeof(empty));

  dfa->dead_state =
      _yr_re_dfa_get_or_create_state(dfa, &empty, 0, &zero_boundaries);

  if (dfa->dead_state == NULL)
    return YR_RE_DFA_RESOURCE_LIMIT;

  for (int i = 0; i < 256; i++)
    dfa->dead_state->next[i] = dfa->dead_state;

  return YR_RE_DFA_OK;
}

// Computes the boundary conditions that hold at "pos", the number of bytes
// consumed since input_data. This mirrors the position tests performed by
// _yr_re_fiber_sync.
static YR_RE_DFA_BOUNDARIES _yr_re_dfa_boundaries_at(
    const uint8_t* input_data,
    size_t input_forwards_size,
    size_t input_backwards_size,
    size_t pos)
{
  YR_RE_DFA_BOUNDARIES boundaries;

  boundaries.at_start = (input_backwards_size == 0 && pos == 0);
  boundaries.at_end = (input_forwards_size == pos);
  boundaries.prev_is_word =
      pos > 0 && _yr_re_dfa_is_word_char(input_data + pos - 1);
  boundaries.cur_is_word =
      pos < input_forwards_size &&
      _yr_re_dfa_is_word_char(input_data + pos);

  return boundaries;
}

// Returns the destination state for the byte "chr", computing and memoizing
// the transition on demand.
static YR_RE_DFA_RESULT _yr_re_dfa_step(
    YR_RE_DFA* dfa,
    YR_RE_DFA_STATE* state,
    uint8_t chr,
    const YR_RE_DFA_BOUNDARIES* boundaries,
    YR_RE_DFA_STATE** next)
{
  if (state == dfa->dead_state)
  {
    *next = dfa->dead_state;
    return YR_RE_DFA_OK;
  }

  // Anchor-free patterns are fully position independent and use the memoized
  // transition table. Patterns with anchors produce position-dependent
  // transitions, so those are recomputed for every input byte.
  if (!dfa->contains_anchor && state->next[chr] != NULL)
  {
    *next = state->next[chr];
    return YR_RE_DFA_OK;
  }

  YR_RE_DFA_STATE* target = NULL;
  YR_RE_DFA_RESULT result = _yr_re_dfa_compute_transition(
      dfa, state, chr, boundaries, &target);

  if (result != YR_RE_DFA_OK)
    return result;

  if (target == NULL)
    target = dfa->dead_state;

  if (!dfa->contains_anchor)
    state->next[chr] = target;

  *next = target;

  return YR_RE_DFA_OK;
}

YR_RE_DFA_RESULT yr_re_dfa_exec(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code,
    const uint8_t* input_data,
    size_t input_forwards_size,
    size_t input_backwards_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args,
    int* matches)
{
  // The DFA only covers single-byte, forward scans. Wide strings and the
  // backwards pass used to extend matches are handled by the fiber engine.
  if (flags & (RE_FLAGS_WIDE | RE_FLAGS_BACKWARDS))
  {
    return YR_RE_DFA_FALLBACK;
  }

  if (yr_re_dfa_is_supported(code) != YR_RE_DFA_OK)
  {
    return YR_RE_DFA_FALLBACK;
  }

  YR_RE_DFA* dfa = _yr_re_dfa_cache_lookup(context, code, flags);

  if (dfa == NULL)
  {
    YR_RE_DFA_RESULT result =
        _yr_re_dfa_cache_create(context, code, flags, &dfa);

    if (result != YR_RE_DFA_OK)
      return result;
  }

  if (dfa->dead_state == NULL)
  {
    YR_RE_DFA_RESULT result = _yr_re_dfa_build_dead_state(dfa);

    if (result != YR_RE_DFA_OK)
      return result;
  }

  if (matches != NULL)
    *matches = -1;

  int max_bytes_matched =
      (int) yr_min(input_forwards_size, (size_t) YR_RE_SCAN_LIMIT);

  bool scan_mode = (flags & RE_FLAGS_SCAN) != 0;

  // In scan mode the automaton is restarted at every input position so that
  // matches starting there are considered, mirroring the fibers spawned by
  // yr_re_exec. In non-scan mode only position zero is tried.
  size_t start_limit = scan_mode ? (size_t) max_bytes_matched : 1;

  for (size_t start = 0; start < start_limit; start++)
  {
    YR_RE_DFA_BOUNDARIES start_boundaries = _yr_re_dfa_boundaries_at(
        input_data,
        input_forwards_size,
        input_backwards_size,
        start);

    YR_RE_DFA_STATE* state = NULL;
    YR_RE_DFA_RESULT start_result =
        _yr_re_dfa_get_start_state(dfa, &start_boundaries, &state);

    if (start_result != YR_RE_DFA_OK)
      return start_result;

    // A zero-length match at the start position.
    if (_yr_re_dfa_state_accepts(state, &start_boundaries))
    {
      YR_RE_DFA_RESULT result = _yr_re_dfa_report_match(
          0,
          max_bytes_matched - (int) start,
          callback,
          callback_args,
          input_data + start,
          flags,
          matches);

      if (result != YR_RE_DFA_OK)
        return result;
    }

    for (size_t pos = start; pos < (size_t) max_bytes_matched; pos++)
    {
      uint8_t chr = input_data[pos];
      YR_RE_DFA_STATE* next = NULL;
      // The byte at "pos" moves the automaton to position pos+1, where any
      // anchor reached through this transition must be evaluated.
      YR_RE_DFA_BOUNDARIES current = _yr_re_dfa_boundaries_at(
          input_data,
          input_forwards_size,
          input_backwards_size,
          pos + 1);

      YR_RE_DFA_RESULT result =
          _yr_re_dfa_step(dfa, state, chr, &current, &next);

      if (result != YR_RE_DFA_OK)
        return result;

      state = next;

      if (_yr_re_dfa_state_accepts(state, &current))
      {
        int match_length = (int) (pos + 1 - start);

        result = _yr_re_dfa_report_match(
            match_length,
            max_bytes_matched - (int) start,
            callback,
            callback_args,
            input_data + start,
            flags,
            matches);

        if (result != YR_RE_DFA_OK)
          return result;
      }

      if (state == dfa->dead_state)
        break;
    }
  }

  return YR_RE_DFA_OK;
}
