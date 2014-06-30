/*
   american fuzzy lop - injectable parts
   -------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file houses the assembly-level instrumentation injected into fuzzed
   programs. The instrumentation stores pairs of data: identifiers of the
   currently executing line and the line that executed immediately before.

   The assembly code shown below is designed for debug-enabled (-g), 32-bit
   x86 output produced by GCC for C/C++ programs. Porting to 64-bit is trivial.

   In principle, similar code should be easy to inject into any well-behaved
   binary-only code (e.g., using DynamoRIO). Calls and jumps offer natural
   targets for instrumentation, and should offer comparable probe density.

 */

#ifndef _HAVE_AFL_AS_H
#define _HAVE_AFL_AS_H

#include "config.h"
#include "types.h"

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

static const u8* trampoline_fmt =

  "\n"
  "/* --- AFL TRAMPOLINE --- */\n"
  "\n"
  ".align 8\n"
  "pushl %%ecx\n"
  "pushl %%eax\n"
  "movl $0x%08x, %%ecx\n"
  "call __afl_maybe_log\n"
  "popl %%eax\n"
  "popl %%ecx\n\n";

static const u8* main_payload = 

  "\n"
  "/* --- AFL MAIN PAYLOAD --- */\n"
  "\n"
  ".text\n"
  ".align 8\n"
  "\n"
  "__afl_maybe_log:\n"
  "\n"
  "  lahf\n"
  "  movb %ah, __afl_saved_flags\n"
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movl __afl_area_ptr, %eax\n"
  "  testl %eax, %eax\n"
  "  je __afl_setup\n"
  "\n"
  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in ecx. */\n"
  "\n"
  "  rorl $8, %ecx\n"
  "\n"
#ifndef COVERAGE_ONLY
  "  xorw __afl_prev_loc, %cx\n"
  "  xorw %cx, __afl_prev_loc\n"
  "  xorw $4095, __afl_prev_loc\n"
#endif /* !COVERAGE_ONLY */
  "  addw %cx, %ax\n"
  "\n"
  "  roll $8, %ecx\n"
#ifdef COVERAGE_ONLY
  "  orb  %cl, (%eax)\n"
#else
  "  xorb %cl, (%eax)\n"
#endif /* ^COVERAGE_ONLY */
  "\n"
  "  movb __afl_saved_flags, %ah\n"
  "  sahf\n"
  "  ret\n"
  "\n"
  ".align 8\n"
  "\n"
  "__afl_setup:\n"
  "\n"
  "  /* Do not retry setup if we had previous failures. */\n"
  "\n"
  "  cmpb $0, __afl_setup_failure\n"
  "  je __afl_setup2\n"
  "\n"
  "__afl_return:\n"
  "\n"
  "  movb __afl_saved_flags, %ah\n"
  "  sahf\n"
  "  ret\n"
  "\n"
  "__afl_setup2:\n"
  "\n"
  "  /* Map SHM, jumping to __afl_setup_abort if something goes wrong. */\n"
  "\n"
  "  pushl %ecx\n"
  "  pushl %edx\n"
  "\n"
  "  pushl $.AFL_SHM_ID\n"
  "  call  getenv\n"
  "  addl  $4, %esp\n"
  "\n"
  "  testl %eax, %eax\n"
  "  je __afl_setup_abort\n"
  "\n"
  "  pushl %eax\n"
  "  call  atoi\n"
  "  addl  $4, %esp\n"
  "\n"
  "  pushl $0          /* shmat flags    */\n"
  "  pushl $0          /* requested addr */\n"
  "  pushl %eax        /* SHM ID         */\n"
  "\n"
  "  call shmat\n"
  "  addl $12, %esp\n"
  "\n"
  "  testl %eax, %eax\n"
  "  je __afl_setup_abort\n"
  "\n"
  "  /* Store the address of the SHM region. */\n"
  "\n"
  "  movl %eax, __afl_area_ptr\n"
  "\n"
  "  popl %edx\n"
  "  popl %ecx\n"
  "\n"
  "  jmp __afl_store\n"
  "\n"
  "__afl_setup_abort:\n"
  "\n"
  "  /* Record setup failure so that we don't keep calling\n"
  "     shmget() / shmat() over and over again. */\n"
  "\n"
  "  incb __afl_setup_failure\n"
  "  popl %edx\n"
  "  popl %ecx\n"
  "  jmp __afl_return\n"
  "\n"
  ".AFL_VARS:\n"
  "\n"
  "  .comm   __afl_area_ptr, 4, 32\n"
  "  .comm   __afl_setup_failure, 1, 32\n"
#ifndef COVERAGE_ONLY
  "  .comm   __afl_prev_loc, 2, 32\n"
#endif /* !COVERAGE_ONLY */
  "  .comm   __afl_saved_flags, 1, 32\n"
  "\n"
  ".AFL_SHM_ID:\n"
  "  .string \"" SHM_ENV_VAR "\"\n"
  "\n";

#endif /* !_HAVE_AFL_AS_H */
