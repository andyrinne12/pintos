#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../threads/thread.h"
#include "../threads/interrupt.h"
#include <list.h>

#define EXIT_FAIL -1
#define EXIT_SUCCESS 0

#define ARG_STEP 4

#define MAX_OPEN_FILES 126
#define MAX_SYSCALL_SIZE 128

#define COMPUTE_ARG_0(x) (x)
#define COMPUTE_ARG_1(x) ((x) + ARG_STEP)
#define COMPUTE_ARG_2(x) ((x) + (2 * ARG_STEP))
#define COMPUTE_ARG_3(x) ((x) + (3 * ARG_STEP))

typedef void (* syscall_func_t)(struct intr_frame *f);

/* File system lock */
struct lock file_sys_lock;

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
