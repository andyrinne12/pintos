#include "../userprog/syscall.h"
#include "../userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "../threads/interrupt.h"
#include "../threads/thread.h"
#include "../threads/vaddr.h"
#include "../threads/malloc.h"
#include "../devices/shutdown.h"
#include "../filesys/filesys.h"
#include "../filesys/file.h"

/* User pointers handling functions */
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t load_number(void *vaddr);
static char * load_address(void *vaddr);
static bool is_valid_buffer (void *baddr, int size);
static bool is_valid_string (const char *str);

static void syscall_handler (struct intr_frame *);

/* System calls functions */
static void halt (void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);

/* File system lock */
struct lock file_sys_lock;

/* List with the open files */
struct list files_opened;

/* structure for the file descriptors */
struct file_descriptor
{
  int num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};


void
syscall_init (void)
{
  lock_init(&file_sys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&files_opened);
}

static void
syscall_handler (struct intr_frame *f)
{
  uint32_t sys_call_number = load_number(f->esp);
  switch (sys_call_number)
	{
	  /* Halt the operating system. */
	  case SYS_HALT:
    {
      halt();
		  break;
    }
	  /* Terminate this process. */
	  case SYS_EXIT:
    {
      int status = *load_address(f->esp + ARG_STEP);
      exit(status);
		  break;
    }
	  /* Start another process. */
	  case SYS_EXEC:
    {
      exec(NULL);
		  break;
    }
	  /* Wait for a child process to die. */
	  case SYS_WAIT:
    {
      wait(0);
      break;
    }
	  /* Create a file. */
	  case SYS_CREATE:
		{
		  const char *file = load_address(COMPUTE_ARG_1(f->esp));
		  unsigned initial_size = *(unsigned *)(COMPUTE_ARG_2(f->esp));

		  f->eax = create (file, initial_size);
		  break;
		}

	  /* Delete a file. */
	  case SYS_REMOVE:
		{
		  const char *file = load_address(COMPUTE_ARG_1(f->esp));
		  f->eax = remove (file);
		  break;
		}

	  /* Open a file. */
	  case SYS_OPEN:
    {
      // const char *file = load_address(COMPUTE_ARG_1(f->esp));
    }
		break;

	  /* Obtain a file's size. */
	  case SYS_FILESIZE:
    {
      int fd = *(int*)(f->esp + 4);
      // const int fd = load_address(COMPUTE_ARG_1(f->esp));
      f->eax = filesize(fd);
    }
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

/* Terminates Pintos */
static void halt(void)
{
  shutdown_power_off();
}

/* Terminates the current user program, sending its exit status to the kernel.*/
static void exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

static pid_t exec (const char* cmd_line)
{
  pid_t pid = process_execute(cmd_line);

  if(pid == TID_ERROR)
    return -1;

  struct thread *cur = thread_current();

  struct child_status *child = malloc(sizeof(struct child_status));

  if(child == NULL){
    // TODO: Handle early termination
    return -1;
  }

  list_push_back(&cur->process_w.children_processes, &child->child_elem);
  child->pid = pid;

  struct thread *child_t;
  child_t = get_thread(pid);

  /* Check if child process is already terminated (successfully or not)
   and if not wait for it to finish loading */
  if(is_thread(child_t) && child_t->status != THREAD_DYING)
    sema_down(&child_t->process_w.loaded_sema);

  /* By this time the child process should have communicated its loaded status
    to its parent */
  if(child->loaded == LOADED_SUCCESS)
    return pid;
  else
    return -1;
}

static int wait (pid_t pid)
{
  return 0;
}

/* Creates a new file called file initially initial size bytes in size.
 * Returns true if successful, false otherwise.
 * Creating a new file does not open it! */
static bool create(const char *file, unsigned initial_size){
  bool result;

  /* Check validity of file string and exit immediately if false */
  if (!is_valid_string(file))
	return false;

  lock_acquire(&file_sys_lock);
  result = filesys_create(file, initial_size);
  lock_release(&file_sys_lock);
  return result;
}

/* Deletes the file called file. Returns true if successful, false otherwise. */
static bool remove(const char *file){
  bool result;

  /* Check validity of file string and exit immediately if false */
  if (!is_valid_string(file))
	return false;

  lock_acquire(&file_sys_lock);
  result = filesys_remove(file);
  lock_release(&file_sys_lock);
  return result;
}

/*Opens the file called file. Returns a non negative integer handle called
 * a “file descriptor” (fd),or -1 if the file could not be opened */
static int open(const char *file){
  struct file_descriptor *fd;
  struct file *new_file;

  /* Check validity of file string and exit immediately if false */
  if(!is_valid_string(file))
    return -1;

  lock_acquire(&file_sys_lock);
  new_file = filesys_open(file);

  if(new_file != NULL){
    fd = calloc(1, sizeof(*fd));
    fd->num++;
    fd->owner = thread_current()->tid;
    fd->file_struct = new_file;
    list_push_back(&files_opened, &fd->elem);
    return fd->num;
  }
  lock_release(&file_sys_lock);
  return -1;
}

/* Returns the size, in bytes, of the file open as fd */
static int filesize (int fd)
{
  struct file_descriptor *descriptor;
  int size = -1;
  lock_acquire (&file_sys_lock);
  // descriptor takes the value of of the open file

  if (descriptor != NULL)
    size = file_length (descriptor->file_struct);

  lock_release (&file_sys_lock);
  return size;
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
 * Otherwise, it terminates the user process. */
static uint32_t load_number(void *vaddr)
{
  if (get_user ((uint8_t *) vaddr) == -1) {
	  exit(EXIT_FAIL);
	}
  return *((uint32_t *) vaddr);
}

/* Receives a memory address and validates it.
 * If successful, it dereferences the stack pointer.
 * Otherwise, it terminates the user process. */
static char* load_address(void *vaddr)
{
  if (get_user ((uint8_t *) vaddr) == -1) {
	  exit(EXIT_FAIL);
	}
  return *((char **) vaddr);
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
static bool is_valid_string (const char *str)
{
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
