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
#include "../src/devices/input.h"

//#define DEBUG

#ifdef DEBUG
#define PRINT(format) (printf(format))
#define PRINT_ONE_ARG(format, arg) (printf(format, arg))
#define PRINT_TWO_ARG(format, arg1, arg2) (printf(format, arg1, arg2))
#endif

#ifndef DEBUG
#define PRINT(format)
#define PRINT_ONE_ARG(format, arg)
#define PRINT_TWO_ARG(format, arg1, arg2)
#endif

/* User pointers handling functions */
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte) UNUSED;
static uint32_t load_number(void *vaddr);
static char * load_address(void *vaddr);
static bool is_valid_buffer (const void *baddr, int size);
static bool is_valid_string (const char *str);

static void syscall_handler (struct intr_frame *);

/* System calls functions */
static void halt (void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int write (int fd, const void * buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close(int fd);
static int read(int fd, void *buffer, unsigned size);

/* Helpers */
static void * find_file(int fd);
static void close_open_file (int fd);

/* File system lock */
static struct lock file_sys_lock;

void
syscall_init (void)
{
  lock_init(&file_sys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
    	  int status = load_number(COMPUTE_ARG_1(f->esp));
    	  exit(status);
		  break;
    	}

	  /* Start another process. */
	  case SYS_EXEC:
    	{
    	  char* cmd_line = load_address(COMPUTE_ARG_1(f->esp));
    	  exec(cmd_line);
		  break;
    	}

	  /* Wait for a child process to die. */
	  case SYS_WAIT:
    	{
    	  pid_t pid = load_number(COMPUTE_ARG_1(f->esp));
    	  wait(pid);
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
    	  const char *file = load_address(COMPUTE_ARG_1(f->esp));
    	  f->eax = open (file);
    	}
		break;

	  /* Obtain a file's size. */
	  case SYS_FILESIZE:
    	{
    	  int fd = *(int*)(COMPUTE_ARG_1(f->esp));
    	  f->eax = filesize (fd);
    	}
		break;

	  /* Read from a file. */
	  case SYS_READ:
    {
      int fd = load_number(COMPUTE_ARG_1(f->esp));
      void *buffer = load_address(COMPUTE_ARG_2(f->esp));
      unsigned size = load_number(COMPUTE_ARG_3(f->esp));
      f->eax = read(fd, buffer, size);
    }
		break;

	  /* Write to a file. */
	  case SYS_WRITE:
		{
		  int fd = load_number(COMPUTE_ARG_1(f->esp));
		  void *buffer = load_address(COMPUTE_ARG_2(f->esp));
		  unsigned size = load_number(COMPUTE_ARG_3(f->esp));
		  f->eax = write(fd, buffer, size);
		}
		break;

	  /* Change position in a file. */
	  case SYS_SEEK:
		{
		  int fd = load_number(COMPUTE_ARG_1(f->esp));
		  unsigned position = load_number(COMPUTE_ARG_2(f->esp));
		  seek(fd, position);
		  break;
		}

	  /* Report current position in a file. */
	  case SYS_TELL:
		{
		  int fd = load_number(COMPUTE_ARG_1(f->esp));
		  f->eax = tell(fd);
		  break;
		}

	  /* Close a file. */
	  case SYS_CLOSE:
		{
		  int fd = load_number(COMPUTE_ARG_1(f->esp));
		  close(fd);
		  break;
		}

	  /* Handle default case. Unrecognized system call. */
	  default:
	    exit(EXIT_FAIL);
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
  thread_current() ->process_w.exit_status = status;
  thread_exit();
}

static pid_t exec (const char* cmd_line)
{
  return process_execute(cmd_line);
}

static int wait (pid_t pid)
{
  return process_wait(pid);
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

/* Opens the file called "file". Returns a non negative integer handle called
 * a “file descriptor” (fd),or -1 if the file could not be opened */
static int open(const char *file){
  struct file_descriptor *fd;
  struct file *new_file;

  /* Check validity of file string and exit immediately if false */
  if(!is_valid_string(file))
    return -1;

  lock_acquire(&file_sys_lock);
  new_file = filesys_open(file);

  if (new_file == NULL)
  {
    lock_release(&file_sys_lock);
  	return -1;
  }

  if (list_size(&thread_current()->files_opened) >= MAX_OPEN_FILES)
  {
    file_close (new_file);
    lock_release(&file_sys_lock);
	return -1;
  }

  fd = calloc(1, sizeof(*fd));
  fd->num = ++thread_current()->fd_count;
  fd->owner = thread_current()->tid;
  fd->file_struct = new_file;
  list_push_back (&thread_current()->files_opened, &fd->elem);

  lock_release (&file_sys_lock);
  return fd->num;
}

/* Returns the size, in bytes, of the file open as fd */
static int filesize (int fd)
{
  struct file_descriptor *descriptor;
  int size = -1;
  lock_acquire (&file_sys_lock);
  // descriptor takes the value of of the open file

  descriptor = find_file(fd);

  /* If any file was found, get its size here */
  if (descriptor != NULL)
    size = file_length (descriptor->file_struct);

  lock_release (&file_sys_lock);
  return size;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of
 * bytes actually written. */
static int write (int fd, const void * buffer , unsigned size)
{
  /* Check validity of buffer and exit immediately if false */
  if(!is_valid_buffer(buffer, size))
	exit(EXIT_FAIL);

  /* Check if write to console is needed and perform it */
  if (fd == STDOUT_FILENO)
  {
	  putbuf (buffer, size);
	  return size;
  }

  /* Find the corresponding file and write */
  struct file_descriptor *descriptor = find_file(fd);

  if (descriptor == NULL)
    exit(EXIT_FAIL);

  lock_acquire (&file_sys_lock);
  int bytes_written = file_write(descriptor->file_struct, buffer, size);
  lock_release (&file_sys_lock);

  return bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position */
static void seek(int fd, unsigned position)
{
  struct file_descriptor *descriptor;
  lock_acquire (&file_sys_lock);

  descriptor = find_file(fd);
  if (descriptor != NULL)
  {
    file_seek (descriptor->file_struct, position);
  }
  lock_release (&file_sys_lock);
}

/* Returns the position of the next byte to be read / written in open file fd */
static unsigned tell (int fd)
{
  int position = 0;
  struct file_descriptor *descriptor;
  lock_acquire (&file_sys_lock);

  descriptor = find_file(fd);
  if (descriptor != NULL){
    position = file_tell (descriptor->file_struct);
  }
  lock_release (&file_sys_lock);
  return position;
}

/* Exiting or terminating a process implicitly closes all its open file
 * descriptors, as if by calling this function for each one. */
static void close (int fd)
{
  struct file_descriptor *descriptor;
  lock_acquire (&file_sys_lock);
  descriptor = find_file (fd);
  if (descriptor != NULL && thread_current ()->tid == descriptor->owner)
  {
    // close the open file
    close_open_file(fd);
  }
  lock_release (&file_sys_lock);
}

static int read(int fd, void *buffer, unsigned size){

  /* Check validity of buffer and exit immediately if false */
  if(!is_valid_buffer(buffer, size))
    exit(EXIT_FAIL);

  if(fd == 0)
  { /* The characters that we are reading have to fill the buffer*/
    uint8_t *copy_buffer = (uint8_t *) buffer;
    for(unsigned i = 0; i < size; i++)
    {
      copy_buffer[i] = input_getc();
    }
  return size;
}
  /* Extract the file */
  lock_acquire (&file_sys_lock);

  struct file_descriptor *descriptor = find_file(fd);

  if(!descriptor)
  {
    exit(EXIT_FAIL);
  }

  int no_of_read_characters = file_read(descriptor->file_struct, buffer, size);

  lock_release (&file_sys_lock);

  return no_of_read_characters;
}

/* Iterate through the opened files and retrieve the one with num = fd */
static void * find_file(int fd)
{
  struct thread *t = thread_current();

  struct list_elem *e;
  for (e = list_begin (&t->files_opened); e != list_end (&t->files_opened);
	   e = list_next (e))
	{
	  struct file_descriptor *file_desc;
	  file_desc = list_entry (e, struct file_descriptor, elem);
	  if (file_desc->num == fd)
		return file_desc;
	}
  return NULL;
}

/* Helper function which iterates through the files opened in order to
 * close the searched file (with the num equal to fd) . */
static void close_open_file (int fd)
{
  struct file_descriptor *descriptor;
  struct list_elem *elem;
  struct list_elem *prev;

  struct list *files_opened= &thread_current()->files_opened;

  elem = list_end (files_opened);
  while (elem != list_head (files_opened))
	{
	  prev = list_prev (elem);
	  descriptor = list_entry (elem, struct file_descriptor, elem);
	  if (descriptor != NULL && fd == descriptor->num)
		{
		  list_remove (elem);
		  file_close (descriptor->file_struct);
		  free (descriptor);
		}
	  elem = prev;
	}
}

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

static bool is_valid_address(const void *addr){
  if (addr == NULL || !is_user_vaddr(addr)){
    exit(EXIT_FAIL);
  }
  return true;
}

/* Handles special case of buffer inspection. */
static bool is_valid_buffer (const void *baddr, int size)
{
  char *buffer = (char *) baddr;
  // if (baddr == NULL || !is_user_vaddr(baddr)){
  //   exit(EXIT_FAIL);
  // }
  for (int i = 1; i < size; i++)
	if (get_user ((uint8_t *) (buffer + i)) == -1)
	  return false;
  return true;
}


/* Handles special case of string inspection. */
static bool is_valid_string (const char *str)
{
  int i = 0;
  int chr = get_user ((uint8_t *) (str + i));

  if(chr == -1)
    exit(EXIT_FAIL);

  while (chr != '\0')
  {
    if (get_user ((uint8_t *) (str + i)) == -1)
      return false;
    else
      chr = get_user ((uint8_t *) (str + i));
    i++;
  }
  return true;
}
