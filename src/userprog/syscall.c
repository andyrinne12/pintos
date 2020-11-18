#include "../devices/shutdown.h"
#include "../filesys/file.h"
#include "../filesys/filesys.h"
#include "../src/devices/input.h"
#include "../threads/interrupt.h"
#include "../threads/malloc.h"
#include "../threads/thread.h"
#include "../threads/vaddr.h"
#include "../userprog/process.h"
#include "../userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>

//#define DEBUG

#ifdef DEBUG
#define PRINT(format) (printf (format))
#define PRINT_ONE_ARG(format, arg) (printf (format, arg))
#define PRINT_TWO_ARG(format, arg1, arg2) (printf (format, arg1, arg2))
#endif

#ifndef DEBUG
#define PRINT(format)
#define PRINT_ONE_ARG(format, arg)
#define PRINT_TWO_ARG(format, arg1, arg2)
#endif

/* User pointers handling functions */
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte) UNUSED;
static uint32_t load_number (void *vaddr);
static char *load_address (void *vaddr);
static bool is_valid_address (const void *addr);
static bool is_valid_buffer (const void *baddr, int size);
static bool is_valid_string (const char *str);

static void syscall_handler (struct intr_frame *);

/* System calls functions */
static void halt(struct intr_frame *f);
static void exit(struct intr_frame *f);
static void exec(struct intr_frame *f);
static void wait(struct intr_frame *f);
static void create(struct intr_frame *f);
static void remove(struct intr_frame *f);
static void open(struct intr_frame *f);
static void filesize(struct intr_frame *f);
static void read(struct intr_frame *f);
static void write(struct intr_frame *f);
static void seek(struct intr_frame *f);
static void tell(struct intr_frame *f);
static void close(struct intr_frame *f);

/* Immediate exit failure */
static void exit_fail(void);

/* Helpers */
static void *find_file (int fd);
static void close_open_file (int fd);
static void close_all_files(void);

/* File system lock */
static struct lock file_sys_lock;

/* System calls array */
static syscall_func_t syscall_func[MAX_SYSCALL_SIZE];

void syscall_init (void)
{
	lock_init (&file_sys_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

	/* Initialize syscall function pointers */
	syscall_func[SYS_HALT] = halt;
	syscall_func[SYS_EXIT] = exit;
	syscall_func[SYS_EXEC] = exec;
  	syscall_func[SYS_WAIT] = wait;
  	syscall_func[SYS_CREATE] = create;
  	syscall_func[SYS_REMOVE] = remove;
  	syscall_func[SYS_OPEN] = open;
  	syscall_func[SYS_FILESIZE] = filesize;
  	syscall_func[SYS_READ] = read;
  	syscall_func[SYS_WRITE] = write;
  	syscall_func[SYS_SEEK] = seek;
  	syscall_func[SYS_TELL] = tell;
  	syscall_func[SYS_CLOSE] = close;
}

static void syscall_handler (struct intr_frame *f)
{
	uint32_t sys_call_number = load_number (f->esp);

	/* Check if system call number is valid */
	if (sys_call_number > SYS_CLOSE)
	  {
		exit_fail ();
		return;
	  }

	/* Check if the arguments passed are valid */
	if (!(is_valid_address(COMPUTE_ARG_1(f->esp))) ||
		!(is_valid_address(COMPUTE_ARG_2(f->esp))) ||
		!(is_valid_address(COMPUTE_ARG_3(f->esp))))
	  {
		exit_fail ();
		return;
	  }

	/* Execute the system call */
	syscall_func[sys_call_number](f);
}

/* Terminates Pintos */
static void halt(struct intr_frame *f UNUSED)
{
  	shutdown_power_off ();
}

/* Terminates the current user program, sending its exit status to the kernel.*/
static void exit(struct intr_frame *f)
{
  	int status = load_number (COMPUTE_ARG_1 (f->esp));
  	close_all_files();
  	thread_current()->process_w.exit_status = status;
  	thread_exit ();
}

/* Function to be called for immediate exit fail */
static void exit_fail(void)
{
  	close_all_files();
  	thread_current()->process_w.exit_status = EXIT_FAIL;
  	thread_exit ();
}

/* Runs the executable whose name is given in cmd line */
static void exec(struct intr_frame *f)
{
  	char *cmd_line = load_address (COMPUTE_ARG_1 (f->esp));
  	f->eax = process_execute(cmd_line);
}

/* Waits for a child process pid and retrieves the child’s exit status. */
static void wait(struct intr_frame *f)
{
  	pid_t pid = load_number (COMPUTE_ARG_1 (f->esp));
  	f->eax = process_wait(pid);
}

/* Creates a new file called file initially initial size bytes in size.
 * Returns true if successful, false otherwise.
 * Creating a new file does not open it! */
static void create(struct intr_frame *f)
{
  	const char *file = load_address (COMPUTE_ARG_1 (f->esp));
  	unsigned initial_size = *(unsigned *) (COMPUTE_ARG_2 (f->esp));
	bool result;

	/* Check validity of file string and exit immediately if false */
	if (!is_valid_string (file))
	{
		f->eax = false;
		return;
	}

	lock_acquire (&file_sys_lock);
	result = filesys_create (file, initial_size);
	lock_release (&file_sys_lock);
  	f->eax = result;
}

/* Deletes the file called file. Returns true if successful, false otherwise. */
static void remove(struct intr_frame *f)
{
  	const char *file = load_address (COMPUTE_ARG_1 (f->esp));
	bool result;

	/* Check validity of file string and exit immediately if false */
	if (!is_valid_string (file))
	  {
		f->eax = false;
		return;
	  }

	lock_acquire (&file_sys_lock);
	result = filesys_remove (file);
	lock_release (&file_sys_lock);
  	f->eax = result;
}

/* Opens the file called "file". Returns a non negative integer handle called
 * a “file descriptor” (fd),or -1 if the file could not be opened */
static void open(struct intr_frame *f)
{
  	const char *file = load_address (COMPUTE_ARG_1 (f->esp));
	struct file_descriptor *fd;
	struct file *new_file;

	/* Check validity of file string and exit immediately if false */
	if (!is_valid_string (file))
	{
		f->eax = -1;
		return;
	}

	lock_acquire (&file_sys_lock);
	new_file = filesys_open (file);

	if (new_file == NULL)
	{
		lock_release (&file_sys_lock);
		f->eax = -1;
		return;
	}

	if (list_size (&thread_current ()->files_opened) >= MAX_OPEN_FILES)
	{
		file_close (new_file);
		lock_release (&file_sys_lock);
		f->eax = -1;
		return;
	}

	fd = calloc (1, sizeof (*fd));
	fd->num = ++thread_current ()->fd_count;
	fd->owner = thread_current ()->tid;
	fd->file_struct = new_file;
	list_push_back (&thread_current ()->files_opened, &fd->elem);

	lock_release (&file_sys_lock);
  	f->eax = fd->num;
}

/* Returns the size, in bytes, of the file open as fd */
static void filesize(struct intr_frame *f)
{
  	int fd = *(int *) (COMPUTE_ARG_1 (f->esp));
  	struct file_descriptor *descriptor;
	int size = -1;
	lock_acquire (&file_sys_lock);

	/* Descriptor takes the value of of the open file */
	descriptor = find_file (fd);

	/* If any file was found, get its size here */
	if (descriptor != NULL)
		size = file_length (descriptor->file_struct);

	lock_release (&file_sys_lock);
  	f->eax = size;
}

/* Reads size bytes from the file open as fd into buffer. */
static void read(struct intr_frame *f)
{
  	int fd = load_number (COMPUTE_ARG_1 (f->esp));
  	void *buffer = load_address (COMPUTE_ARG_2 (f->esp));
  	unsigned size = load_number (COMPUTE_ARG_3 (f->esp));

  	/* Check validity of buffer and exit immediately if false */
  	if (!is_valid_buffer (buffer, size))
		exit_fail();

  	if (fd == STDIN_FILENO)
	{
	  /* The characters that we are reading have to fill the buffer*/
	  uint8_t *copy_buffer = (uint8_t *) buffer;
	  for (unsigned i = 0; i < size; i++)
		copy_buffer[i] = input_getc ();
	  f->eax = size;
	  return;
	}

  	/* Extract the file */
  	lock_acquire (&file_sys_lock);
  	struct file_descriptor *descriptor = find_file (fd);

  	if (!descriptor)
	  {
		lock_release (&file_sys_lock);
		exit_fail ();
		return;
	  }

  	int no_of_read_characters = file_read (descriptor->file_struct, buffer, size);
  	lock_release (&file_sys_lock);

  	f->eax = no_of_read_characters;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of
 * bytes actually written. */
static void write(struct intr_frame *f)
{
  	int fd = load_number (COMPUTE_ARG_1 (f->esp));
  	void *buffer = load_address (COMPUTE_ARG_2 (f->esp));
  	unsigned size = load_number (COMPUTE_ARG_3 (f->esp));

	/* Check validity of buffer and exit immediately if false */
	if (!is_valid_buffer (buffer, size))
		exit_fail();

	/* Check if write to console is needed and perform it */
	if (fd == STDOUT_FILENO)
	{
		putbuf (buffer, size);
		f->eax = size;
		return;
	}

	/* Find the corresponding file and write */
    lock_acquire (&file_sys_lock);

	struct file_descriptor *descriptor = find_file (fd);

	if (!descriptor)
	  {
		lock_release (&file_sys_lock);
		exit_fail ();
		return;
	  }

	int bytes_written = file_write (descriptor->file_struct, buffer, size);
	lock_release (&file_sys_lock);

  	f->eax = bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position */
static void seek(struct intr_frame *f)
{
  	int fd = load_number (COMPUTE_ARG_1 (f->esp));
	unsigned position = load_number (COMPUTE_ARG_2 (f->esp));

	struct file_descriptor *descriptor;
	lock_acquire (&file_sys_lock);

	descriptor = find_file (fd);
	if (descriptor != NULL)
	{
		file_seek (descriptor->file_struct, position);
	}
	lock_release (&file_sys_lock);
}

/* Returns the position of the next byte to be read / written in open file fd */
static void tell(struct intr_frame *f)
{
  	int fd = load_number (COMPUTE_ARG_1 (f->esp));
	int position = 0;
	struct file_descriptor *descriptor;
	lock_acquire (&file_sys_lock);

	descriptor = find_file (fd);
	if (descriptor != NULL)
	{
		position = file_tell (descriptor->file_struct);
	}
	lock_release (&file_sys_lock);
  	f->eax = position;
}

/* Exiting or terminating a process implicitly closes all its open file
 * descriptors, as if by calling this function for each one. */
static void close(struct intr_frame *f)
{
  	int fd = load_number (COMPUTE_ARG_1 (f->esp));
	struct file_descriptor *descriptor;
	lock_acquire (&file_sys_lock);
	descriptor = find_file (fd);
	if (descriptor != NULL && thread_current ()->tid == descriptor->owner)
	{
		/* close the open file */
		close_open_file (fd);
	}
	lock_release (&file_sys_lock);
}

/* Iterate through the opened files and retrieve the one with num = fd */
static void *find_file (int fd)
{
	struct thread *t = thread_current ();

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

/* Helper function which closes the requested file and frees resources. */
static void close_open_file (int fd)
{
	struct file_descriptor *descriptor = find_file(fd);

	list_remove(&descriptor->elem);
  	file_close (descriptor->file_struct);
	free (descriptor);
}

/* When exiting, make sure all files belonging to this thread are closed */
static void close_all_files(void)
{
  	struct thread *curr = thread_current ();

  	struct list_elem *e;
  	lock_acquire (&file_sys_lock);
  	while (!list_empty (&curr->files_opened))
  	  {
	  	e = list_begin (&curr->files_opened);
	  	int fd = list_entry (e,
	  	struct file_descriptor, elem)->num;
	  	struct file_descriptor *descriptor = find_file (fd);
	  	if (descriptor != NULL && curr->tid == descriptor->owner)
			close_open_file (fd);
	  }
  	lock_release (&file_sys_lock);
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int get_user (const uint8_t *uaddr)
{
	/* Check user address is below PHYS_BASE here to avoid adding this
	 * pre-condition to the function and make sure it is met. */
	if (!is_user_vaddr (uaddr))
		return -1;

	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
	return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte)
{
	/* Check user address is below PHYS_BASE here to avoid adding this
	 * pre-condition to the function and make sure it is met. */
	if (!is_user_vaddr (udst))
		return false;

	int error_code;
	asm("movl $1f, %0; movb %b2, %1; 1:"
	    : "=&a"(error_code), "=m"(*udst)
	    : "q"(byte));
	return error_code != -1;
}

/* Receives a memory address and validates it.
 * If successful, it dereferences the stack pointer.
 * Otherwise, it terminates the user process. */
static uint32_t load_number (void *vaddr)
{
	if (get_user ((uint8_t *) vaddr) == -1)
	{
		exit_fail();
	}
	return *((uint32_t *) vaddr);
}

/* Receives a memory address and validates it.
 * If successful, it dereferences the stack pointer.
 * Otherwise, it terminates the user process. */
static char *load_address (void *vaddr)
{
	if (get_user ((uint8_t *) vaddr) == -1)
	{
		exit_fail();
		return NULL;
	}
	return *((char **) vaddr);
}

/* Checks if the address is valid and corresponds to a user pointer */
static bool is_valid_address (const void *addr)
{
	if (addr == NULL || !is_user_vaddr (addr))
		return false;
	return true;
}

/* Handles special case of buffer inspection. */
static bool is_valid_buffer (const void *baddr, int size)
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
	int chr = get_user ((uint8_t *) (str + i));

	if (chr == -1)
		return false;

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
