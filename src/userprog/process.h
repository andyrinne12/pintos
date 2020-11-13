#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>

#define ARGS_MAX_SIZE 128 /* Maximum space allocated for arguments in stack */
#define ARGS_MAX_COUNT 31 /* Maximum number of arguments passed to program */

#define LOADED_SUCCESS 0
#define LOADED_FAILED -1

typedef int pid_t;

struct child_status
{
  pid_t pid;                            /* Child process pid */
  struct list_elem child_elem;          /* Children list elem */
  int exit_status;                      /* Process exit status */
};

/* Computes the next adress where a byte should start */
#define last_address_alligned(X) (X - (uint32_t) X % 4)

pid_t process_execute (const char *file_name);
int process_wait (pid_t child_pid);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
