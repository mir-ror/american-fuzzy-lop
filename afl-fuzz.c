/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>

#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/resource.h>


static u8 *in_dir,                    /* Directory with initial testcases */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir;                   /* Working & output directory       */

static u32 exec_tmout = EXEC_TIMEOUT, /* Configurable exec timeout (ms)   */
           mem_limit = MEM_LIMIT;     /* Memory cap for the child process */

static u8  skip_deterministic,        /* Skip deterministic stages?       */
           skip_det_input,            /* Skip for input files only?       */
           dumb_mode,                 /* Allow non-instrumented code?     */
           unique_only,               /* Skip non-unique crashes & hangs? */
           kill_signal;               /* Signal that killed the child     */

static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom,               /* Persistent fd for /dev/urandom   */
           dev_null;                  /* Persistent fd for /dev/null      */

static s32 child_pid;                 /* PID of the fuzzed program        */

static u8* trace_bits;                /* SHM with instrumentation bitmap  */
static u8  virgin_bits[4096];         /* Regions yet untouched by fuzzing */

static s32 shm_id;                    /* ID of the SHM region             */

static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
                   clear_screen,      /* Window resized?                  */
                   child_timed_out;   /* Traced process timed out?        */

static u64 unique_queued,             /* Total number of queued testcases */
           variable_queued,           /* Testcases with variable behavior */
           initial_queued,            /* Total number of initial inputs   */
           unique_processed,          /* Number of finished queue entries */
           total_crashes,             /* Total number of crashes          */
           unique_crashes,            /* Crashes with unique signatures   */
           total_hangs,               /* Total number of hangs            */
           unique_hangs,              /* Hangs with unique signatures     */
           queued_later,              /* Items queued after 1st cycle     */
           abandoned_inputs,          /* Number of abandoned inputs       */
           total_execs,               /* Total execvp() calls             */
           start_time,                /* Unix start time (ms)             */
           last_path_time,            /* Time for most recent path (ms)   */
           last_crash_time,           /* Time for most recent crash (ms) */
           queue_cycle;               /* Queue round counter              */

static u32 subseq_hangs;              /* Number of hangs in a row         */

static u8* stage_name;                /* Name of the current fuzz stage   */
static s32 stage_cur, stage_max;      /* Stage progression                */

static u64 stage_finds[13],           /* Patterns found per fuzz stage    */
           stage_cycles[13];          /* Execs per fuzz stage             */

static u32 rand_cnt;                  /* Random number counter            */

static u64 total_cal_time,            /* Total calibration time (ms)      */
           total_cal_cycles;          /* Total calibration cycles         */

static u64 total_bitmap_size,         /* Total bitmap size (calibration)  */
           total_bitmap_entries;      /* Total bitmap entries             */

static u32 perf_score;                /* Perf score for queue entry       */

struct queue_entry {
  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */
  u8  det_done;                       /* Deterministic stage done?        */
  u8  init_done;                      /* Init done?                       */
  u32 exec_time;                      /* Execution time (ms)              */
  u32 bitmap_size;                    /* Bitmap size                      */
  u64 handicap;                       /* Number of queue cycles behind    */
  struct queue_entry* next;           /* Next element, if any             */
};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */
                          *queue_top; /* Top of the list                  */


/* Interesting values, as per config.h */

static u8  interesting_8[]  = { INTERESTING_8 };
static u16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static u32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* Fuzzing stages */

enum {
  STAGE_FLIP1,
  STAGE_FLIP2,
  STAGE_FLIP4,
  STAGE_FLIP8,
  STAGE_FLIP16,
  STAGE_FLIP32,
  STAGE_ARITH8,
  STAGE_ARITH16,
  STAGE_ARITH32,
  STAGE_INTEREST8,
  STAGE_INTEREST16,
  STAGE_INTEREST32,
  STAGE_HAVOC
};


/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);

}


/* Generate a random number (from 0 to limit - 1) */

static inline u32 UR(u32 limit) {

  if (!(rand_cnt++ % RESEED_RNG)) {

    u32 seed;

    if (read(dev_urandom, &seed, sizeof(seed)) != sizeof(seed))
      PFATAL("Short read from /dev/urandom");

    srandom(seed);

  }

  return random() % limit;


}


/* Append new test case to the queue. */

static void add_to_queue(u8* fname, u32 len) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len   = len;

  if (queue_top) {

    queue_top->next = q;
    queue_top = q;

  } else queue = queue_top = q;

  unique_queued++;

  if (queue_cycle > 1) queued_later++;

  last_path_time = get_cur_time();

}


/* Destroy the entire queue. */

static void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q);
    q = n;

  }

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. */

static inline u8 has_new_bits(void) {

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_bits;

  u32  i = (4096 >> 2);
  u8   ret = 0;

  while (i--) {

    if (*current & *virgin) {
      *virgin &= ~*current;
      ret = 1;
    }

    current++;
    virgin++;

  }

  return ret;

}


/* Count the number of bits set in the provided bitmap. */

static inline u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (4096 >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24;

  }

  return ret;

}


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {
  shmctl(shm_id, IPC_RMID, NULL);
}


/* Configure shared memory. */

static void setup_shm(void) {

  u8* shm_str;

  memset(virgin_bits, 255, 4096);

  shm_id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");

}


/* Read all testcases from the input directory, then queue them for testing. */

static void read_testcases(void) {

  DIR* d = opendir(in_dir);
  struct dirent* de;
  struct queue_entry* q;

  if (!d) PFATAL("Unable to open '%s'", in_dir);

  while ((de = readdir(d))) {

    struct stat st;
    u8* fn = alloc_printf("%s/%s", in_dir, de->d_name);
 
    if (stat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big", fn);

    if (!st.st_size) 
      FATAL("Test case '%s' has zero length, doesn't seem useful", fn);

    add_to_queue(fn, st.st_size);

  }

  if (!unique_queued) FATAL("No usable test cases in '%s'", in_dir);

  if (skip_det_input) {

    q = queue;

    while (q) {
      q->det_done = 1;
      q = q->next;
    }

  }

  q = queue;

  while (q) {
    q->init_done = 1;
    q = q->next;
  } 

  last_path_time = 0;
  initial_queued = unique_queued;

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

#define FAULT_NONE   0
#define FAULT_HANG   1
#define FAULT_CRASH  2
#define FAULT_ERROR  3

static u8 run_target(char** argv) {

  static struct itimerval it;
  int status;

  child_timed_out = 0;

  memset(trace_bits, 0, 4096);

  child_pid = fork();

  if (child_pid < 0) PFATAL("fork() failed");

  if (!child_pid) {

    struct rlimit r;

    r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

    setrlimit(RLIMIT_AS, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null, 1);
    dup2(dev_null, 2);

    if (out_file) {

      dup2(dev_null, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    close(dev_null);

    execvp(argv[0], argv);

    /* Use a distinctive return value to tell the parent about execvp()
       falling through. */

    exit(EXEC_FAIL);

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  if (waitpid(child_pid, &status, WUNTRACED) <= 0) PFATAL("waitpid() failed");

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Report outcome to caller. */

  if (child_timed_out) return FAULT_HANG;

  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);
    return FAULT_CRASH;
  }

  if (WEXITSTATUS(status) == EXEC_FAIL) return FAULT_ERROR;

  return 0;

}


/* Perform dry run of all test cases to confirm that the app is working as
   expected. */

static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;

  while (q) {

    u8  fault, warned = 0;
    u32 i, cksum, cal_cycles = CAL_CYCLES;
    u8  new_bits = 0;
    u64 start_time, stop_time;

    ACTF("Verifying test case '%s'...", q->fname);

    if (!out_file) {

      out_fd = open(q->fname, O_RDONLY);
      if (out_fd < 0) PFATAL("Unable to open '%s'", q->fname);

    } else {

      unlink(out_file); /* Ignore errors. */
      if (link(q->fname, out_file)) PFATAL("link() failed");

    }

    start_time = get_cur_time();

    fault = run_target(argv);
    if (stop_soon) return;

    switch (fault) {

      case FAULT_HANG:  FATAL("Test case '%s' results in a hang (adjusting -t "
                              "may help)", q->fname);

      case FAULT_CRASH: FATAL("Test case '%s' results in a crash", q->fname);

      case FAULT_ERROR: FATAL("Unable to execute target application ('%s')",
                              argv[0]);

    }

    if (!dumb_mode) {

      if (!count_bits(trace_bits))
        FATAL("No instrumentation detected (you can always try -n)");

      if (has_new_bits()) new_bits = 1;

    }

    if (stop_soon) return;

    cksum = hash32(trace_bits, 4096, 0xa5b35705);

    for (i = 0; i < cal_cycles; i++) {

      u32 new_cksum;

      if (!out_file) lseek(out_fd, 0, SEEK_SET);
      fault = run_target(argv);

      if (stop_soon) return;

      switch (fault) {

        case FAULT_HANG:  FATAL("Test case '%s' results in intermittent hangs "
                                "(adjusting -t may help)", q->fname);

        case FAULT_CRASH: FATAL("Test case '%s' results in intermittent "
                                "crashes", q->fname);

        case FAULT_ERROR: FATAL("Unable to execute target application (huh)");

      }

      new_cksum = hash32(trace_bits, 4096, 0xa5b35705);

      if (cksum != new_cksum) {

        if (!warned) {
          WARNF("Instrumentation output varies across runs.");
          warned = 1;
          variable_queued++;
          cal_cycles = CAL_CYCLES_LONG;
        }

        if (has_new_bits()) new_bits = 1;

      }

    }

    stop_time = get_cur_time();

    total_cal_time   += stop_time - start_time;
    total_cal_cycles += cal_cycles;

    q->exec_time   = (stop_time - start_time) / cal_cycles;
    q->bitmap_size = count_bits(trace_bits);
    q->handicap    = 0;
    q->init_done   = 1;

    total_bitmap_size     += q->bitmap_size;
    total_bitmap_entries  += 1;

    if (!out_file) close(out_fd);

    if (!dumb_mode && !new_bits) {
      WARNF("No new instrumentation output, test case may be redundant.");
    }

    OKF("Done: %u bits set, %u remaining in the bitmap.", 
         count_bits(trace_bits), count_bits(virgin_bits));

    q = q->next;

  }

}


/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif /* !O_NOFOLLOW */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (write(fd, mem, len) != len) 
    PFATAL("Short write to output file");

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* Check if the result of a test run is interesting, save or queue the input
   test case for further analysis if so. */

static void save_if_interesting(void* mem, u32 len, u8 fault) {

  u8 *fn = "", *dir;
  s32 fd;
  u32 hash = 0;

  switch (fault) {

    case FAULT_NONE:

      if (!has_new_bits()) return;
      fn = alloc_printf("%s/queue/%06llu-%06llu", out_dir, unique_queued,
                        unique_processed);
      add_to_queue(fn, len);
      break;

    case FAULT_HANG:

      if (!dumb_mode) hash = hash32(trace_bits, 4096, 0xa5be5705);
      dir = alloc_printf("%s/hangs/%08x", out_dir, hash);

      if (!mkdir(dir, 0700) || dumb_mode) {

        unique_hangs++;

      } else if (!unique_only) {

        total_hangs++;
        ck_free(dir);
        return;

      }

      fn = alloc_printf("%s/%06llu-%06llu", dir, total_hangs, unique_processed);
      ck_free(dir);
      total_hangs++;
      break;

    case FAULT_CRASH:

      dir = alloc_printf("%s/crashes/signal-%02u", out_dir, kill_signal);
      mkdir(dir, 0700); /* Ignore errors */
      ck_free(dir);

      if (!dumb_mode) hash = hash32(trace_bits, 4096, 0xa5be5705);
      dir = alloc_printf("%s/crashes/signal-%02u/%08x", out_dir, kill_signal,
                         hash);

      if (!mkdir(dir, 0700) || dumb_mode) {
 
        unique_crashes++;
        last_crash_time = get_cur_time();

      } else if (!unique_only) {

        total_crashes++;
        ck_free(dir);
        return;

      }

      fn = alloc_printf("%s/%06llu-%06llu", dir, total_crashes,
                        unique_processed);
      ck_free(dir);
      total_crashes++;
      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

  }

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'\n", fn);

  if (write(fd, mem, len) != len) PFATAL("Short write to '%s'", fn);

  if (fault) ck_free(fn);

  close(fd);

}


/* Display some fuzzing stats. */

static void show_stats(void) {

  s64 cur_ms, run_time;

  u32 run_d, run_h, run_m;
  double run_s;

  u32 vbits = (4096 << 3) - count_bits(virgin_bits);

  cur_ms   = get_cur_time();
  run_time = cur_ms - start_time;

  if (!run_time) run_time = 1;

  run_d = run_time / 1000 / 60 / 60 / 24;
  run_h = (run_time / 1000 / 60 / 60) % 24;
  run_m = (run_time / 1000 / 60) % 60;
  run_s = ((double)(run_time % 60000)) / 1000;

  if (clear_screen) {

    SAYF(TERM_CLEAR);
    clear_screen = 0;

  }

  SAYF(TERM_HOME cCYA 
       "afl-fuzz " cBRI VERSION cYEL "\n--------------\n\n"

       cCYA "Queue cycle: " cBRI "%llu\n\n"

       cGRA 
       "    Overall run time : " cNOR "%u day%s, %u hr%s, %u min, %0.02f sec"
       "    \n", queue_cycle,
       run_d, (run_d == 1) ? "" : "s", run_h, (run_h == 1) ? "" : "s",
       run_m, run_s);

  SAYF(cGRA
       "      Problems found : %s%llu " cNOR "crashes (%llu unique), "
       "%llu hangs (%llu unique)\n",
       total_crashes ? cLRD : cNOR,
       total_crashes, unique_crashes, total_hangs, unique_hangs);


  if (last_path_time) {

    s64 path_diff;
    u32 path_d, path_h, path_m;
    double path_s;

    path_diff = cur_ms - last_path_time;

    path_d = path_diff / 1000 / 60 / 60 / 24;
    path_h = (path_diff / 1000 / 60 / 60) % 24;
    path_m = (path_diff / 1000 / 60) % 60;

    path_s = ((double)(path_diff % 60000)) / 1000;

    SAYF(cGRA
         "       Last new path : " cNOR "%u day%s, %u hr%s, %u min, %0.02f sec"
         " ago    \n", 
         path_d, (path_d == 1) ? "" : "s", path_h, (path_h == 1) ? "" : "s",
         path_m, path_s);

  } else {

    SAYF(cGRA
         "       Last new path : " cNOR "none seen yet\n");

  }

  if (last_crash_time) {

    s64 crash_diff;
    u32 crash_d, crash_h, crash_m;
    double crash_s;

    crash_diff = cur_ms - last_crash_time;

    crash_d = crash_diff / 1000 / 60 / 60 / 24;
    crash_h = (crash_diff / 1000 / 60 / 60) % 24;
    crash_m = (crash_diff / 1000 / 60) % 60;

    crash_s = ((double)(crash_diff % 60000)) / 1000;

    SAYF(cGRA
         "   Last unique crash : " cNOR "%u day%s, %u hr%s, %u min, %0.02f sec"
         " ago    \n", 
         crash_d, (crash_d == 1) ? "" : "s", crash_h, (crash_h == 1) ? "" : "s",
         crash_m, crash_s);

  } else {

    SAYF(cGRA
         "   Last unique crash : " cNOR "none seen yet\n");

  }

  SAYF(cCYA "\nIn-depth stats:\n\n" cGRA
       "     Execution paths : " cNOR "%llu+%llu/%llu done "
       "(%0.02f%%), %llu variable        \n", unique_processed, abandoned_inputs,
       unique_queued, ((double)unique_processed + abandoned_inputs) * 100 /
       unique_queued, variable_queued);


  SAYF(cGRA
       "       Current stage : " cNOR "%s, %u/%u done (%0.02f%%)           \n",
       stage_name, stage_cur, stage_max, ((double)stage_cur) * 100 / stage_max);

  SAYF(cGRA
       "    Execution cycles : " cNOR "%llu (%0.02f per second)    \n",
       total_execs, ((double)total_execs) * 1000 / run_time);

  SAYF(cGRA
       "      Bitmap density : " cNOR "%u tuples seen (%0.02f%%)\n",
       vbits, ((double)vbits) * 100 / (4096 << 3));

  SAYF(cGRA
       "  Fuzzing efficiency : " cNOR "path = %0.02f, crash = %0.02f, hang = %0.02f ppm"
       cRST "        \n", ((double)unique_queued - initial_queued) * 1000000 / total_execs,
       ((double)unique_crashes) * 1000000 / total_execs,
       ((double)unique_hangs) * 1000000 / total_execs);

  SAYF(cGRA "\n"
       "     Bit flip yields : " cNOR "%llu/%llu, %llu/%llu, %llu/%llu\n",
        stage_finds[STAGE_FLIP1], stage_cycles[STAGE_FLIP1],
        stage_finds[STAGE_FLIP2], stage_cycles[STAGE_FLIP2],
        stage_finds[STAGE_FLIP4], stage_cycles[STAGE_FLIP4]);

  SAYF(cGRA
       "    Byte flip yields : " cNOR "%llu/%llu, %llu/%llu, %llu/%llu\n",
        stage_finds[STAGE_FLIP8], stage_cycles[STAGE_FLIP8],
        stage_finds[STAGE_FLIP16], stage_cycles[STAGE_FLIP16],
        stage_finds[STAGE_FLIP32], stage_cycles[STAGE_FLIP32]);

  SAYF(cGRA
       "  Arithmetics yields : " cNOR "%llu/%llu, %llu/%llu, %llu/%llu\n",
        stage_finds[STAGE_ARITH8], stage_cycles[STAGE_ARITH8],
        stage_finds[STAGE_ARITH16], stage_cycles[STAGE_ARITH16],
        stage_finds[STAGE_ARITH32], stage_cycles[STAGE_ARITH32]);

  SAYF(cGRA
       "    Known int yields : " cNOR "%llu/%llu, %llu/%llu, %llu/%llu\n",
        stage_finds[STAGE_INTEREST8], stage_cycles[STAGE_INTEREST8],
        stage_finds[STAGE_INTEREST16], stage_cycles[STAGE_INTEREST16],
        stage_finds[STAGE_INTEREST32], stage_cycles[STAGE_INTEREST32]);

  SAYF(cGRA
       "  Havoc stage yields : " cNOR "%llu/%llu (%llu latent paths)" cRST "\n\n",
        stage_finds[STAGE_HAVOC], stage_cycles[STAGE_HAVOC], queued_later);

  fflush(stdout);

}


/* Write a modified test case, run program, process results. Handle
   error conditions. */

static u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  write_to_testcase(out_buf, len);

  fault = run_target(argv);

  if (stop_soon) return 1;

  if (fault == FAULT_HANG && subseq_hangs++ > HANG_LIMIT) {

    abandoned_inputs++;
    return 1;

  } else subseq_hangs = 0;

  save_if_interesting(out_buf, len, fault);

  if (!(stage_cur % 100) || stage_cur + 1 == stage_max) show_stats();

  return 0;

}


/* Take the first entry from the queue, fuzz it for a while. This
   function is a tad too long... */

static void fuzz_one(char** argv) {

  s32 len, fd, temp_len;
  u8  *in_buf, *out_buf;
  s32 i, j;
  u64 havoc_queued;
  u32 avg_exec_time, avg_bitmap_size;
  u64 orig_hit_cnt, new_hit_cnt;

  /* Read the test case into memory, remove file if appropriate. */

  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  in_buf  = ck_alloc(len),
  out_buf = ck_alloc(len);

  if (read(fd, in_buf, len) != len)
    PFATAL("Short read from '%s'", queue_cur->fname);

  close(fd);

  memcpy(out_buf, in_buf, len);

  subseq_hangs = 0;
  perf_score   = 100;

  /***************
   * CALIBRATION *
   ***************/

  if (!queue_cur->init_done) {

    u64 start_time, stop_time;

    u32 cksum, new_cksum;
    u8  var_detected = 0;

    stage_name = "calibration";
    stage_max  = CAL_CYCLES;

    start_time = get_cur_time();

    write_to_testcase(out_buf, len);
    run_target(argv);
    cksum = hash32(trace_bits, 4096, 0xa5b35705);

    for (stage_cur = 1; stage_cur < stage_max; stage_cur++) {

      write_to_testcase(out_buf, len);
      run_target(argv);
      if (stop_soon) goto abandon_entry;

      new_cksum = hash32(trace_bits, 4096, 0xa5b35705);

      if (cksum != new_cksum) {

        has_new_bits();

        if (!var_detected) {

          u8* new_fn;

          variable_queued++;
          var_detected = 1;

          new_fn = alloc_printf("%s-variable", queue_cur->fname);
         
          if (rename(queue_cur->fname, new_fn))
            PFATAL("Unable to rename '%s'", queue_cur->fname);

          ck_free(queue_cur->fname);
          queue_cur->fname = new_fn;
      
          
        }

      }

      show_stats();

    }

    stop_time = get_cur_time();

    total_cal_time   += stop_time - start_time;
    total_cal_cycles += stage_max;

    queue_cur->exec_time   = (stop_time - start_time) / stage_max;
    queue_cur->bitmap_size = count_bits(trace_bits);
    queue_cur->handicap    = queue_cycle;
    queue_cur->init_done   = 1;

    total_bitmap_size     += queue_cur->bitmap_size;
    total_bitmap_entries  += 1;

  }

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  /* Classify execution speed */

  avg_exec_time = total_cal_time / total_cal_cycles;

  if (queue_cur->exec_time * 0.1 > avg_exec_time) perf_score = 10;
  else if (queue_cur->exec_time * 0.25 > avg_exec_time) perf_score = 25;
  else if (queue_cur->exec_time * 0.5 > avg_exec_time) perf_score = 50;
  else if (queue_cur->exec_time * 0.75 > avg_exec_time) perf_score = 75;
  else if (queue_cur->exec_time * 3 < avg_exec_time) perf_score = 300;
  else if (queue_cur->exec_time * 2 < avg_exec_time) perf_score = 200;
  else if (queue_cur->exec_time * 1.5 < avg_exec_time) perf_score = 150;

  /* Classify bitmap size */

  avg_bitmap_size = total_bitmap_size / total_bitmap_entries;

  if (queue_cur->bitmap_size * 0.7 > avg_bitmap_size) perf_score *= 3;
  else if (queue_cur->bitmap_size * 0.8 > avg_bitmap_size) perf_score *= 2;
  else if (queue_cur->bitmap_size * 0.9 > avg_bitmap_size) perf_score *= 1.5;
  else if (queue_cur->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;
  else if (queue_cur->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (queue_cur->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;

  /* Adjust score based on handicap */

  if (queue_cur->handicap >= 4) {
    perf_score *= 4;
    queue_cur->handicap -= 3;
  } else if (queue_cur->handicap) {
    perf_score *= 2;
    queue_cur->handicap--;
  }

  if (skip_deterministic || queue_cur->det_done) goto havoc_stage;

  /******************
   * SIMPLE BITFLIP *
   ******************/

#define FLIP_BIT(_ar, _b) do { _ar[(_b) >> 3] ^= (1 << ((_b) & 7)); } while (0)

  stage_name = "bitflip 1/1";
  stage_max  = len << 3;

  orig_hit_cnt = unique_queued + unique_crashes;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

  stage_name = "bitflip 2/1";
  stage_max  = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  stage_name = "bitflip 4/1";
  stage_max  = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  stage_name = "bitflip 8/8";
  stage_max  = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    out_buf[stage_cur] ^= 0xFF;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  if (len < 2) goto skip_bitflip;

  stage_name = "bitflip 16/8";
  stage_max  = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    *(u16*)(out_buf + stage_cur) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    *(u16*)(out_buf + stage_cur) ^= 0xFFFF;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4) goto skip_bitflip;

  stage_name = "bitflip 32/8";
  stage_max  = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    *(u32*)(out_buf + stage_cur) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    *(u32*)(out_buf + stage_cur) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  stage_name = "arith 8/8";
  stage_cur  = 0;
  stage_max  = 2 * len * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    for (j = 1; j <= ARITH_MAX; j++) {

      out_buf[i] += j;

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
      stage_cur++;

      out_buf[i] -= 2 * j;

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
      stage_cur++;

      out_buf[i] += j;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;

  if (len < 2) goto skip_arith;

  stage_name = "arith 16/8";
  stage_cur  = 0;
  stage_max  = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    for (j = 1; j <= ARITH_MAX; j++) {

      if ((orig & 0xff) + j > 0xff) {

        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j) {

        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) + j > 0xff) {

        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j) {

        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  if (len < 4) goto skip_arith;

  stage_name = "arith 32/8";
  stage_cur  = 0;
  stage_max  = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    for (j = 1; j <= ARITH_MAX; j++) {

      if ((orig & 0xffff) + j > 0xffff) {

        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig & 0xffff) < j) {

        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff) {

        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((SWAP32(orig) & 0xffff) < j) {

        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u32*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name = "interest 8/8";
  stage_cur  = 0;
  stage_max  = len * sizeof(interesting_8);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    for (j = 0; j < sizeof(interesting_8); j++) {

      if (interesting_8[j] == orig) {
        stage_max--;
        continue;
      }

      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  if (len < 2) goto skip_interest;

  stage_name = "interest 16/8";
  stage_cur  = 0;
  stage_max  = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      if (interesting_16[j] != orig) {

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if (SWAP16(interesting_16[j]) != interesting_16[j] && 
          SWAP16(interesting_16[j]) != orig) {

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;


    }

    *(u16*)(out_buf + i) = orig;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  if (len < 4) goto skip_interest;

  stage_name = "interest 32/8";
  stage_cur  = 0;
  stage_max  = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      if (interesting_32[j] != orig) {

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if (SWAP32(interesting_32[j]) != interesting_32[j] && 
          SWAP32(interesting_32[j]) != orig) {

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u32*)(out_buf + i) = orig;

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  queue_cur->det_done = 1;

  stage_name = "havoc";
  stage_max  = HAVOC_CYCLES * perf_score / 100;

  temp_len = len;

  orig_hit_cnt = unique_queued + unique_crashes;

  havoc_queued = unique_queued;
 
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << UR(HAVOC_STACK_POW2);
 
    for (i = 0; i < use_stacking; i++) {

      switch (UR(15)) {

        case 0:

          /* Flip a single bit */

          FLIP_BIT(out_buf, UR(temp_len << 3));

          break;

        case 1: 

          /* Set byte to interesting value */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value */

          if (temp_len < 2) break;

          if (UR(2)) {

            *(u16*)(out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value */

          if (temp_len < 4) break;

          if (UR(2)) {
  
            *(u32*)(out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value */

          out_buf[UR(temp_len)] = UR(256);
          break;

        case 11: {

            /* Delete bytes */

            u32 del_from, del_len, max_chunk_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            max_chunk_len = MIN((temp_len - 1) * HAVOC_MAX_PERCENT / 100,
                                HAVOC_MAX_BLOCK);

            del_len = 1 + UR(max_chunk_len ? max_chunk_len : 1);

            del_from = UR(temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;

          }

        case 12: {

            /* Clone bytes */

            u32 clone_from, clone_to, clone_len, max_chunk_len;
            u8* new_buf;

            max_chunk_len = MIN(temp_len * HAVOC_MAX_PERCENT / 100,
                                HAVOC_MAX_BLOCK);

            clone_len  = 1 + UR(max_chunk_len ? max_chunk_len : 1);

            clone_from = UR(temp_len - clone_len + 1);
            clone_to   = UR(temp_len);

            new_buf = ck_alloc(temp_len + clone_len);

            /* Head */
            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */
            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

            break;

          }

        case 13: {

            /* Overwrite bytes */

            u32 copy_from, copy_to, copy_len, max_chunk_len;

            if (temp_len < 2) break;

            max_chunk_len = MIN((temp_len - 1) * HAVOC_MAX_PERCENT / 100,
                                HAVOC_MAX_BLOCK);

            copy_len  = 1 + UR(max_chunk_len ? max_chunk_len : 1);

            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (copy_from != copy_to)
              memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            break;

          }

        case 14: {

            /* Memset bytes */

            u32 set_from, set_len, max_chunk_len;

            max_chunk_len = MIN(temp_len * HAVOC_MAX_PERCENT / 100,
                                HAVOC_MAX_BLOCK);

            set_len  = 1 + UR(max_chunk_len ? max_chunk_len : 1);

            set_from = UR(temp_len - set_len + 1);

            memset(out_buf + set_from, R(256), set_len);

            break;

          }


      }

    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* Run for a bit longer when new finds are being made. */

    if (unique_queued != havoc_queued) {

      if (stage_max / HAVOC_MAX_MULT < HAVOC_CYCLES * perf_score / 100)
        stage_max *= 2;

      havoc_queued = unique_queued;

    }

  }

  new_hit_cnt = unique_queued + unique_crashes;

  stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_HAVOC] += stage_max;

  unique_processed++;

abandon_entry:

  ck_free(in_buf);
  ck_free(out_buf);

}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 
  if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Handle timeout. */

static void handle_timeout(int sig) {

  child_timed_out = 1; 
  if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/traced_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for captured crashes\n\n"

       "Execution control settings:\n\n"

       "  -f file       - input filed used by the traced application\n"
       "  -t msec       - timeout for each run (%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n\n"
      
       "Fuzzing behavior settings:\n\n"

       "  -d            - skip all deterministic fuzzing stages\n"
       "  -D            - skip deterministic fuzzing for input files only\n"
       "  -n            - fuzz non-instrumented binaries (dumb mode)\n"
       "  -u            - do not store non-unique samples on disk\n\n"

       "For additional tips, please consult the provided documentation.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT);

  exit(1);

}


/* Prepare output directories. */

static void setup_dirs(void) {

  u8* tmp;

  if (mkdir(out_dir, 0700) && errno != EEXIST)
    PFATAL("Unable to create '%s'", out_dir);

  tmp = alloc_printf("%s/queue", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

  tmp = alloc_printf("%s/crashes", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

  tmp = alloc_printf("%s/hangs", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

}


/* Setup the output file for fuzzed data. */

static void setup_stdio_file(void) {

  u8* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}


/* Handle screen resize. */

static void handle_resize(int sig) {
  clear_screen = 1;
}



/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cNOR " (" __DATE__ " " __TIME__ 
       ") by <lcamtuf@google.com>\n");

  signal(SIGHUP,   handle_stop_sig);
  signal(SIGINT,   handle_stop_sig);
  signal(SIGTERM,  handle_stop_sig);
  signal(SIGALRM,  handle_timeout);
  signal(SIGWINCH, handle_resize);

  signal(SIGTSTP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  while ((opt = getopt(argc,argv,"+i:o:f:m:t:dDnu")) > 0)

    switch (opt) {

      case 'i':

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;
        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 't':

        exec_tmout = atoi(optarg);
        if (exec_tmout < 50) FATAL("Bad or dangerously low value of -t");
        break;

      case 'm':

        mem_limit = atoi(optarg);
        if (mem_limit < 10) FATAL("Bad or dangerously low value of -m");
        break;

      case 'd':

        skip_deterministic = 1;
        break;

      case 'D':

        skip_det_input = 1;
        break;

      case 'u':

        unique_only = 1;
        break;

      case 'n':

        dumb_mode = 1;
        break;

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  if (dumb_mode && unique_only)
    FATAL("-n and -u are not compatible with each other");

  if (skip_deterministic && skip_det_input)
    FATAL("-d and -D are mutually exclusive");

  dev_null = open("/dev/null", O_RDWR);
  if (dev_null < 0) PFATAL("Unable to open /dev/null");

  dev_urandom = open("/dev/urandom", O_RDONLY);
  if (dev_urandom < 0) PFATAL("Unable to open /dev/urandom");

  start_time = get_cur_time();

  setup_shm();

  setup_dirs();

  read_testcases();

  perform_dry_run(argv + optind);

  if (!stop_soon) {

    usleep(500000);
    if (!out_file) setup_stdio_file();

  }

  SAYF(TERM_CLEAR);

  while (!stop_soon) {

    if (!queue_cur) {

      queue_cycle++;
      unique_processed  = 0;
      abandoned_inputs  = 0;
      queue_cur = queue;
      show_stats();

    }

    fuzz_one(argv + optind);
    queue_cur = queue_cur->next;

  }

  show_stats();

  if (stop_soon) SAYF(cLRD "\n+++ Testing aborted by user +++\n" cRST);

  destroy_queue();
  alloc_report();

  OKF("We're done here. Have a nice day!");

  exit(0);

}

