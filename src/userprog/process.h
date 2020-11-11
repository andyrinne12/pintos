#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include <list.h>

#define ARGS_MAX_SIZE 128 /* Maximum space allocated for arguments in stack */
#define ARGS_MAX_COUNT 16 /* Maximum number of arguments passed to program */

typedef int pid_t;

struct child_process
{
  pid_t pid;                            /* Child process pid */
  struct list_elem child_elem;          /* Children list elem */
  int loaded;                           /* Process loaded (1 if true) */
  int exit_status;                      /* Process exit status */
};

struct process_wrapper
{
  pid_t parent_pid;                     /* Parent process pid */
  struct semaphore loaded_sema;         /* Process loaded semaphore */
  struct semaphore finished_sema;       /* Process finished semaphore */
  struct list children_processes;       /* Children processes */
};

/* Computes the next adress where a byte should start */
#define last_address_alligned(X) (X - (uint32_t) X % 4)

pid_t process_execute (const char *file_name);
int process_wait (pid_t child_pid);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
