#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define EXIT_FAIL -1
#define EXIT_SUCCESS 0

#define ARG_STEP 4

#define COMPUTE_ARG_0(x) (x)
#define COMPUTE_ARG_1(x) ((x) + ARG_STEP)
#define COMPUTE_ARG_2(x) ((x) + (2 * ARG_STEP))

void syscall_init (void);

#endif /* userprog/syscall.h */
