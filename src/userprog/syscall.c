#include "../userprog/syscall.h"
#include "../userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "../threads/interrupt.h"
#include "../threads/thread.h"
#include "../threads/vaddr.h"
#include "../devices/shutdown.h"
#include "../filesys/filesys.h"
// #include <stdlib.h>
#include <malloc.h>

/* User pointers handling functions */
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t load_memory_address(void *vaddr);
static bool is_valid_buffer (void *baddr, int size);
static bool is_valid_string (void *straddr);

static void syscall_handler (struct intr_frame *);

/* System calls functions */
static void halt (void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  uint32_t sys_call_number = load_memory_address(f->esp);
  switch (sys_call_number)
	{
	  /* Halt the operating system. */
	  case SYS_HALT:
	    halt();
		  break;
	  /* Terminate this process. */
	  case SYS_EXIT:
	    exit(0);
		  break;
	  /* Start another process. */
	  case SYS_EXEC:
      exec(NULL);
		  break;
	  /* Wait for a child process to die. */
	  case SYS_WAIT:
      wait(0);
      break;
	  /* Create a file. */
	  case SYS_CREATE:
    {
      const char* file = *(char**)(f->esp + 1);
      unsigned initial_size = *(unsigned*)(f->esp + 2);
      f->eax = create(file, initial_size);
      break;
    }
	  /* Delete a file. */
	  case SYS_REMOVE:
    {
      const char* file = *(char**)(f -> esp + 1);
      f->eax = remove(file);
      break;
    }
	  /* Open a file. */
	  case SYS_OPEN:
		break;
	  /* Obtain a file's size. */
	  case SYS_FILESIZE:
		break;
	  /* Read from a file. */
	  case SYS_READ:
		break;
	  /* Write to a file. */
	  case SYS_WRITE:
		break;
	  /* Change position in a file. */
	  case SYS_SEEK:
		break;
	  /* Report current position in a file. */
	  case SYS_TELL:
		break;
	  /* Close a file. */
	  case SYS_CLOSE:
		break;
	  /* Handle default case. Unrecognized system call. */
	  default:
		break;
	}
}

static void halt(void)
{
  shutdown_power_off();
}

static void exit(int status)
{
  printf("%s: exit(%d)", thread_current()->name, status);
  thread_exit();
}

static pid_t exec (const char* cmd_line)
{
  pid_t pid = process_execute(cmd_line);

  if(pid == TID_ERROR)
  return -1;

  struct thread *cur = thread_current();

  struct child_process *child = malloc(sizeof(struct child_process));

  if(child == NULL){
  // TODO: Handle early termination
  }

  child->pid = pid;

  return pid;
}

static int wait (pid_t pid)
{
  return 0;
}

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
static uint32_t load_memory_address(void *vaddr)
{
  if (get_user ((uint8_t *) vaddr) == -1) {
	  exit(EXIT_FAIL);
	}
  return *((uint32_t *) vaddr);
}

/* Handles special case of buffer inspection. */
static bool is_valid_buffer (void *baddr, int size)
{
  char *buffer = (char *) baddr;
  for (int i = 1; i < size; i++)
	if (get_user ((uint8_t *) (buffer + i)) == -1)
	  return false;
  return true;
}

/* Handles special case of string inspection. */
static bool is_valid_string (void *straddr)
{
  char *str = (char *) straddr;
  int i = 0;
  int chr = get_user ((uint8_t *) (str + i));;
  while (chr != '\0') {
	  i++;
	  if (get_user ((uint8_t *) (str + i)) == -1)
		return false;
	  else
		chr = get_user ((uint8_t *) (str + i));
	}
  return true;
}

// -----------------------------------------------------------------

static bool create(const char *file, unsigned initial_size){
  bool result;
  result = is_valid_string(file);
  // lock_acquire();
  result = filesys_create(file, initial_size);
  // lock_release();
  return result;
}

static bool remove(const char *file){
  bool result;
  is_valid_string(file);
  // lock_acquire();
  result = filesys_remove(file);
  // lock_release();
  return result;
}
