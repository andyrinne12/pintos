#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../threads/thread.h"
#include <list.h>

#define EXIT_FAIL -1
#define EXIT_SUCCESS 0

#define ARG_STEP 4

#define COMPUTE_ARG_0(x) (x)
#define COMPUTE_ARG_1(x) ((x) + ARG_STEP)
#define COMPUTE_ARG_2(x) ((x) + (2 * ARG_STEP))

/* structure for the file descriptors */
struct file_descriptor
{
  int num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

void syscall_init (void);

#endif /* userprog/syscall.h */
