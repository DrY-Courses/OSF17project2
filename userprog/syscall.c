#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include "lib/log.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "lib/kernel/console.h"
#include "lib/user/syscall.h"
#include "threads/synch.h"

#define LOGGING_LEVEL 6

static void syscall_handler (struct intr_frame *);
static struct lock file_lock;

bool
is_valid_address(void* addr)
{

/*
	int i;
	for(i = 0; i < 4; ++i)
	{
		if(addr + i == NULL || !is_user_vaddr(addr+i) || pagedir_get_page(thread_current()->pagedir,addr + i) == NULL)
		{
			return false;
		}
	}
	return true;
*/


	if (addr > PHYS_BASE) {
		sys_exit(-1);
		return false;
	}
return true;
}

struct file_map*
find_fd(struct thread* t, int fd)
{
	struct list_elem *e;
	for (e = list_begin(&t->files); e != list_end(&t->files); e = list_next(e))
	{
		struct file_map* fmap = list_entry(e, struct file_map, file_elem);
		if(fmap->fd == fd)
		{
			return fmap;
		}
	}
	return NULL;
}

void
syscall_init (void)
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&thread_current()->file_lock);
}

/*
 *  Implement the system call handler in "userprog/syscall.c".
 *  The skeleton implementation we provide "handles" system calls
 *  by terminating the process. It will need to retrieve the system call number,
 *  then any system call arguments, and carry out appropriate actions.

	Implement the following system calls.
	The prototypes listed are those seen by a user program that includes "lib/user/syscall.h".
	(This header, and all others in "lib/user", are for use by user programs only.)
	System call numbers for each system call are defined in "lib/syscall-nr.h":
 * */


/*
System Call: void halt (void)
	Terminates Pintos by calling shutdown_power_off()
	(declared in "threads/init.h"). This should be seldom used,
	because you lose some information about possible deadlock situations, etc.
 */
void
sys_halt(void)
{
	shutdown_power_off();
}

/*
System Call: void exit (int status)
	Terminates the current user program, returning status to the kernel.
	If the process's parent waits for it (see below), this is the status
	that will be returned. Conventionally, a status of 0 indicates success
	and nonzero values indicate errors.
 */
void
sys_exit(int status)
{
	printf("%s: exit(%d)\n",thread_name(), status);
	struct thread *t = thread_current();
	*(t->exitStatus) = status;
	log(L_TRACE, "\n\n\n\nsys_exit with tid = %d & exitStatus = %d", t->tid, *(t->exitStatus));
	thread_exit();
}

/*
System Call: pid_t exec (const char *cmd_line)
    Runs the executable whose name is given in cmd_line, passing any given arguments,
    and returns the new process's program id (pid). Must return pid -1,
    which otherwise should not be a valid pid, if the program cannot load or run
    for any reason. Thus, the parent process cannot return from the exec until
    it knows whether the child process successfully loaded its executable.
    You must use appropriate synchronization to ensure this.
 */
int
sys_exec(char *cmd_line)
{
	int executePID = 0;
	executePID = process_execute(cmd_line);
	return executePID;
}

/*
System Call: int wait (pid_t pid)
    Waits for a child process pid and retrieves the child's exit status.

    If pid is still alive, waits until it terminates. Then, returns
    the status that pid passed to exit. If pid did not call exit(),
    but was terminated by the kernel (e.g. killed due to an exception),
    wait(pid) must return -1. It is perfectly legal for a parent process
    to wait for child processes that have already terminated by the time
    the parent calls wait, but the kernel must still allow the parent to
    retrieve its child's exit status, or learn that the child
    was terminated by the kernel.

    wait must fail and return -1 immediately if any of the
    following conditions is true:

        * pid does not refer to a direct child of the calling process.
        	pid is a direct child of the calling process if and only
        	if the calling process received pid as a return value
        	from a successful call to exec.

        * Note that children are not inherited:
         	if A spawns child B and B spawns child process C, then
         	A cannot wait for C, even if B is dead. A call to wait(C)
         	by process A must fail. Similarly, orphaned processes are
         	not assigned to a new parent if their parent process exits before they do.

        * The process that calls wait has already called wait on pid.
         	That is, a process may wait for any given child at most once.

    Processes may spawn any number of children, wait for them in any order,
    and may even exit without having waited for some or all of their children.
    Your design should consider all the ways in which waits can occur.
    All of a process's resources, including its struct thread, must be
    freed whether its parent ever waits for it or not, and regardless of
    whether the child exits before or after its parent.

    You must ensure that Pintos does not terminate until the initial process exits.
    The supplied Pintos code tries to do this by calling process_wait()
    (in "userprog/process.c") from main() (in "threads/init.c").
    We suggest that you implement process_wait() according to the comment
    at the top of the function and then implement the
    wait system call in terms of process_wait().

    Implementing this system call requires considerably more work than any of the rest.

 */
int
sys_wait(int pid)
{
	int process_wait_returnValue = 0;
	process_wait_returnValue = process_wait(pid);
	return process_wait_returnValue;
}

/*
System Call: bool create (const char *file, unsigned initial_size)
    Creates a new file called file initially initial_size bytes in size.
    Returns true if successful, false otherwise.
    Creating a new file does not open it: opening the new file is a
    separate operation which would require a open system call.
 */
bool
sys_create(char *file, int initial_size)
{
	log(L_TRACE, "We're in sys_create");
	bool success = false; // returns true if successfully create file

	lock_acquire(&thread_current()->file_lock);
	success = filesys_create(file,initial_size);
	lock_release(&thread_current()->file_lock);

	return success;
}

/*
System Call: bool remove (const char *file)
    Deletes the file called file. Returns true if successful, false otherwise.
    A file may be removed regardless of whether it is open or closed, and removing
    an open file does not close it. See Removing an Open File, for details.
 */
bool
sys_remove(char *file)
{
	log(L_TRACE, "We're in sys_remove, file is %s", file);
	bool success = false; // returns true if successful

	lock_acquire(&thread_current()->file_lock);

	success = filesys_remove(file); // remove file from system

	lock_release(&thread_current()->file_lock);
	return success;
}

/*

System Call: int open (const char *file)
    Opens the file called file. Returns a nonnegative integer handle called
    a "file descriptor" (fd), or -1 if the file could not be opened.

    File descriptors numbered 0 and 1 are reserved for the console: fd 0 (
    STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output.
    The open system call will never return either of these file descriptors,
    which are valid as system call arguments only as explicitly described below.

    Each process has an independent set of file descriptors.
    File descriptors are not inherited by child processes.

    When a single file is opened more than once, whether by a single process
    or different processes, each open returns a new file descriptor.
    Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position.

 */
int
sys_open(char *file)
{
	log(L_TRACE, "We're in sys_open, file is %s", file);
	int fd = -1; // returns file descriptor or -1 if file cant be opened

	lock_acquire(&thread_current()->file_lock);

	struct thread *t = thread_current();
	struct file_map* fmap = (struct file_map*) malloc(sizeof(struct file_map));

	if(&file != NULL){
			struct file* open_file = filesys_open(file);
			if(open_file)
			{
				fmap->fd = ++t->next_fd;
				fmap->file = open_file;
				list_push_back(&t->files, &fmap->file_elem);
				fd = fmap->fd;
			}
	}

	return fd;
}

/*
System Call: int filesize (int fd)
    Returns the size, in bytes, of the file open as fd.
 */
int
sys_filesize(int fd)
{
		log(L_TRACE, "We're in sys_filesize, fd is %d", fd);
	int filesize = -1;

	lock_acquire(&thread_current()->file_lock);
	struct thread* t = thread_current();

	struct file_map* f = find_fd(t, fd);
	filesize = f ? file_length(f->file) : -1;


	lock_release(&thread_current()->file_lock);
	return filesize;
}

/*

System Call: int read (int fd, void *buffer, unsigned size)
    Reads size bytes from the file open as fd into buffer. Returns the
    number of bytes actually read (0 at end of file), or -1 if the file
    could not be read (due to a condition other than end of file).
    Fd 0 reads from the keyboard using input_getc().
 */
int
sys_read(int fd, void *buffer, int size)
{
		log(L_TRACE, "We're in sys_read, fd is %d", fd);
	int bytes_read; // number of bytes actually read
	char* buff = buffer;

	lock_acquire(&thread_current()->file_lock); // lock file

	if(fd == STDIN_FILENO){ // read from console
		unsigned int i = 0;
		for(i = 0; i < size; ++i) // get size number of characters
		{
			buff[i] = input_getc();
		}
		bytes_read = size;
	}
	else // reading from file
	{
		struct file_map* f = find_fd(thread_current(), fd);
		bytes_read = f ? file_read(f->file,buff,size) : -1;
	}

	lock_release(&thread_current()->file_lock); // release lock on file
	return bytes_read;
}

/*

System Call: int write (int fd, const void *buffer, unsigned size)
    Writes size bytes from buffer to the open file fd. Returns the number
    of bytes actually written, which may be less than size
    if some bytes could not be written.

    Writing past end-of-file would normally extend the file, but file growth
    is not implemented by the basic file system. The expected behavior is to
    write as many bytes as possible up to end-of-file and return the actual
    number written, or 0 if no bytes could be written at all.

    Fd 1 writes to the console. Your code to write to the console should write
    all of buffer in one call to putbuf(), at least as long as size is not bigger
    than a few hundred bytes. (It is reasonable to break up larger buffers.)
    Otherwise, lines of text output by different processes may end up interleaved
    on the console, confusing both human readers and our grading scripts.

 */
int
sys_write(int fd, void *buffer, unsigned size)
{
		log(L_TRACE, "We're in sys_write, fd is %d", fd);
	int bytes_written = 0; // initialize returned size
	char* buff = buffer;

	lock_acquire(&thread_current()->file_lock); // lock the file so others cant access it

	if (fd == STDOUT_FILENO) // call putbuf() if writing to console
	{
		putbuf(buff,size);
		bytes_written = size;
	}
	else // writing to file
	{
		struct file_map* f = find_fd(thread_current(), fd);
		bytes_written = file_write(f->file,buff,size);
	}

	lock_release(&thread_current()->file_lock); // release lock on file
	return bytes_written;

}

/*

System Call: void seek (int fd, unsigned position)
    Changes the next byte to be read or written in open file fd to position,
    expressed in bytes from the beginning of the file.
    (Thus, a position of 0 is the file's start.)

    A seek past the current end of a file is not an error. A later read obtains
    0 bytes, indicating end of file. A later write extends the file, filling
    any unwritten gap with zeros. (However, in Pintos files have a fixed length
    until project 4 is complete, so writes past end of file will return an error.)
    These semantics are implemented in the file system and do not require any
    special effort in system call implementation.

 */
void
sys_seek(int fd, int position)
{
	log(L_TRACE, "We're in sys_seek, fd is %d", fd);

	lock_acquire(&thread_current()->file_lock); // lock the file

	struct file_map* f = find_fd(thread_current(), fd);
	if(f) file_seek(f->file,position);

	lock_release(&thread_current()->file_lock);
}

/*

System Call: unsigned tell (int fd)
    Returns the position of the next byte to be read or written in open file fd,
    expressed in bytes from the beginning of the file.
 */
int
sys_tell(int fd)
{
	log(L_TRACE, "We're in sys_tell, fd is %d", fd);

	int nbp; // next byte position

	lock_acquire(&thread_current()->file_lock);

	struct file_map* f = find_fd(thread_current(), fd);
	nbp = file_tell(f->file);

	lock_release(&thread_current()->file_lock);
	return nbp;
}

/*

System Call: void close (int fd)
    Closes file descriptor fd. Exiting or terminating a process implicitly closes
    all its open file descriptors, as if by calling this function for each one.
 */
void
sys_close(int fd)
{
	log(L_TRACE, "We're in sys_close, fd is %d", fd);

	lock_acquire(&thread_current()->file_lock);
	struct thread* t = thread_current();

	if(fd != STDIN_FILENO && fd != STDOUT_FILENO)
	{
		struct file_map* f = find_fd(thread_current(), fd);
		list_remove(&f->file_elem); // im a litte iffy on this... trying to remove element from file list
		file_close(f->file); // close file
		free(f); // no longer need map for file, freedom!
	}

	lock_release(&thread_current()->file_lock);
}



static void
syscall_handler (struct intr_frame *f)
{
	log(L_TRACE, "syscall handler hit");

	lock_init(&thread_current()->file_lock);
	//is_valid_address(f);
	is_valid_address(f->esp);
	void* stack_ptr = f->esp + 4;
	int syscall_no = *(int*) (f->esp);

	char *file;
	int fd;
	void *buffer;
	unsigned size;
	unsigned position;
	int initial_size;
	int status;
	volatile char* cmd_line;
	int pid;
	int i;
	struct thread *current_thread;

	switch (syscall_no) {
		case SYS_HALT:
			log(L_TRACE, "SYS_HALT");
			sys_halt();
			break;

		case SYS_EXIT:
			log(L_TRACE, "SYS_EXIT");
			is_valid_address(stack_ptr);
			status = *(int*) (stack_ptr);
			f->eax = status;
			sys_exit(status);
			break;
		case SYS_EXEC:
			log(L_TRACE, "SYS_EXEC");
			//stack_ptr = f->esp + 4;
			cmd_line = *(char**)stack_ptr;
			log(L_TRACE, "sys_exec case with cmd_line = %s", cmd_line);
			is_valid_address(cmd_line);
			for(i = 0; i < strlen(cmd_line); ++i){
				is_valid_address(cmd_line + i);
			}
			f->eax = sys_exec(cmd_line);
			break;

		case SYS_WAIT:
			log(L_TRACE, "SYS_WAIT");
			pid = *(int*)stack_ptr;
			f->eax = sys_wait(pid);
			break;

		case SYS_CREATE:
			log(L_TRACE, "SYS_CREATE");
			file = *(char**)stack_ptr;
			stack_ptr += 4;
			initial_size = *(int*)stack_ptr;
			is_valid_address(file);
			for(i = 0; i < strlen(file); ++i){
				is_valid_address(file + i);
			}

			f->eax = sys_create(file, initial_size);
			break;

		case SYS_REMOVE:
			log(L_TRACE, "SYS_REMOVE");
			file = *(char**)stack_ptr;
			is_valid_address(file);
			for(i = 0; i < strlen(file); ++i){
				is_valid_address(file + i);
			}
			f->eax = sys_remove(file);
			break;
		case SYS_OPEN:
//			log(L_TRACE, "SYS_OPEN");
			file = *(char**)stack_ptr;
			is_valid_address(file);
			for(i = 0; i < strlen(file); ++i){
				is_valid_address((file + i));
			}
			f->eax = sys_open(file);
			break;

		case SYS_FILESIZE:
//			log(L_TRACE, "SYS_FILESIZE");
			fd = *(int*)stack_ptr;
			f->eax = sys_filesize(fd);
			break;

		case SYS_READ:
			fd = *(int*)stack_ptr;
			stack_ptr += 4;
			buffer = *(void**)stack_ptr;
			stack_ptr += 4;
			size = *(int*)stack_ptr;
			is_valid_address(buffer);
			f->eax = sys_read(fd, buffer, size);
			break;

		case SYS_WRITE:
//			log(L_TRACE, "SYS_WRITE");
			fd = *(int*)stack_ptr;
			stack_ptr += 4;
			buffer = *(void**)stack_ptr;
			stack_ptr += 4;
			size = *(unsigned*)stack_ptr;
			is_valid_address(buffer);
			f->eax = sys_write(fd, buffer, size);
			break;

		case SYS_SEEK:
//			log(L_TRACE, "SYS_SEEK");
			fd = *(int*)stack_ptr;
			stack_ptr += 4;
			position = *(int*)stack_ptr;
			sys_seek(fd, position);
			break;

		case SYS_TELL:
//			log(L_TRACE, "SYS_TELL");
			fd = *(int*)stack_ptr;
			f->eax = sys_tell(fd);
			break;

		case SYS_CLOSE:
//			log(L_TRACE, "SYS_CLOSE");
			fd = *(int*)stack_ptr;
			sys_close(fd);
			break;
		default:
			log(L_TRACE, "Default case hit for syscall handler, unhandled error: %d", f->error_code);
	}
}
