#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define ARGS_MAX_SIZE 128 /* Maximum space allocated for arguments in stack */
#define ARGS_MAX_COUNT 16 /* Maximum number of arguments passed to program */

/* Computes the next adress where a byte should start */
#define last_address_alligned(X) (X - (uint32_t) X % 4)

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
