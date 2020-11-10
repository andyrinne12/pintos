#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../threads/vaddr.h"

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t load_memory_address(void *vaddr);

static void syscall_handler (struct intr_frame *);

// -----------------------------------------------------------------

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
  /* Check user address is below PHYS_BASE here to avoid adding this
   * pre-condition to the function and make sure it is met. */
  if (!is_user_vaddr (uaddr))
    return -1;

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
  : "=&a" (result) : "m" (*uaddr));
  return result;
}
/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  /* Check user address is below PHYS_BASE here to avoid adding this
   * pre-condition to the function and make sure it is met. */
  if (!is_user_vaddr (udst))
	return false;

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
  : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Receives a memory address and validates it.
 * If successful, it dereferences the stack pointer.
 * Otherwise, it terminates the user process.*/
static uint32_t load_memory_address(void *vaddr){
  if (get_user ((uint8_t *) vaddr) == -1) {
	  // call the exit system call with an error code
  }
  return *((uint32_t *) vaddr);
}

// -----------------------------------------------------------------

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
