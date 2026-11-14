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

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef YR_RE_DFA_H
#define YR_RE_DFA_H

#include <yara/re.h>
#include <yara/types.h>

// Result codes returned by the DFA engine. YR_RE_DFA_OK means that the DFA
// was able to run the regular expression to completion. YR_RE_DFA_FALLBACK
// means that the bytecode uses a construct that the DFA can't emulate, in
// which case the caller must run the original backtracking engine.
typedef enum _YR_RE_DFA_RESULT
{
  YR_RE_DFA_OK = 0,
  YR_RE_DFA_FALLBACK = 1,
  YR_RE_DFA_RESOURCE_LIMIT = 2
} YR_RE_DFA_RESULT;

// Checks whether the regular expression bytecode can be executed by the DFA
// engine. This is a cheap, allocation-free scan over the opcodes. It returns
// YR_RE_DFA_FALLBACK when an unsupported opcode (for example the masked
// literals used by hex strings or the "any" repetition operator) is found.
YR_RE_DFA_RESULT yr_re_dfa_is_supported(const uint8_t* code);

// Executes a regular expression using a lazily-constructed DFA. The argument
// list mirrors yr_re_exec() so that the two engines can be used
// interchangeably. The DFA cache is stored in the scan context and shared by
// all the regular expressions executed during a scan.
//
// Returns YR_RE_DFA_OK when the DFA handled the execution, or
// YR_RE_DFA_FALLBACK / YR_RE_DFA_RESOURCE_LIMIT when the caller must retry
// with yr_re_exec().
YR_RE_DFA_RESULT yr_re_dfa_exec(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code,
    const uint8_t* input_data,
    size_t input_forwards_size,
    size_t input_backwards_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args,
    int* matches);

// Destroys all the DFA objects cached in the scan context. Called once when
// the scanner is destroyed.
void yr_re_dfa_cache_destroy(YR_SCAN_CONTEXT* context);

// Returns true the first time it is called for a given bytecode pointer during
// a scan, and false afterwards. Callers use it to emit a DFA fallback message
// at most once per regular expression instead of on every match attempt.
bool yr_re_dfa_mark_fallback_notified(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code);

#endif
