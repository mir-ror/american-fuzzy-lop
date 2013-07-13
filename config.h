/*
   american fuzzy lop - vaguely configurable bits
   ----------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#include "types.h"

/* Maximum allocator request size (keep well under INT_MAX): */

#define MAX_ALLOC           0x40000000

/* Maximum size of input file (keep under 100MB): */

#define MAX_FILE            (1 * 1000 * 1000)

/* Comment out to disable terminal colors: */

#define USE_COLOR

/* Maximum line length passed from GCC to 'as': */

#define MAX_AS_LINE         8192

/* Default timeout for fuzzed code (milliseconds): */

#define EXEC_TIMEOUT        3000

/* Default memory limit for child process (MB): */

#define MEM_LIMIT           100

/* Number of calibration cycles per every new test case: */

#define CAL_CYCLES          10
#define CAL_CYCLES_LONG     100

/* Uncomment to be pedantic about instrumentation output for input files: */

/* Distinctive exit code used to indicate failed execution: */

#define EXEC_FAIL           0x55

/* Maximum number of subsequent hangs before abandoning an input file: */

#define HANG_LIMIT          20

/* Number of random tweaks during a single 'havoc' stage: */

#define HAVOC_CYCLES        5000

/* Max havoc stacking (the average is half of this amount): */

#define HAVOC_STACKING      10

/* Caps on block size for cloning and deletion operation: */

#define HAVOC_MAX_BLOCK     100
#define HAVOC_MAX_PERCENT   75

/* Interval between reseeding PRNG (values returned): */

#define RESEED_RNG          10000

/* Environment variable used to pass SHM ID to the called program. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

/* Uncomment this to use inferior coverage-based instrumentation. */

// #define COVERAGE_ONLY

/* List of interesting values to use in fuzzing. */

#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100000000,    /* Large negative number (100M)            */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100000000,    /* Large positive number (100M)            */ \
   2147483647    /* Overflow signed 32-bit when incremented */

#endif /* ! _HAVE_CONFIG_H */
