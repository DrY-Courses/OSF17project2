#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/log.h"
#include "lib/kernel/console.h"

#define LOGGING_LEVEL 6

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void setupTokens(const char* fn);
void setupStack(void **esp);
void placeTokensOnStack(void **esp);
void pushArgv(void **esp);
char mutableString[1000];
char* tokens[100];
int tokenCount;
char* pointersToTokensOnStack[100];

struct child_p {
    char* name;
    int* exitStatus;
    struct semaphore* semaUpInStartProcess;
	struct semaphore* semaUpInProcessExit;
	bool* successfullyLoaded;
};


//did not use union
union mysp {
    uint8_t *byte;
    uint32_t *word;
};

void setupTokens(const char* fn) {
  char* savePtr;
  int i;
  for(i = 0; fn[i] != 0; i++) {
    mutableString[i] = fn[i];
  }
  mutableString[i] = 0;
  //tokenize to global variable "tokens"
  char* token = strtok_r(mutableString, " ", &savePtr);
  for (i = 0; token != NULL; i++) {
    tokens[i] = token;
    token = strtok_r(NULL, " ", &savePtr);
  }
  tokenCount = i;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  //tokenizes filename into global array "tokens"
  setupTokens(file_name);
  char *fn_copy;
  char *file_name1;
  tid_t tid;
  char* filename1_strtok_reentry;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  file_name1 = malloc(strlen(file_name + 1));
  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (file_name1, file_name, PGSIZE);
  file_name1 = strtok_r(file_name1, " ", &filename1_strtok_reentry);
  struct child_p *child = (struct child_p *) malloc(sizeof(struct child_p*));
  child->semaUpInStartProcess = malloc(sizeof(struct semaphore));
  child->semaUpInProcessExit = malloc(sizeof(struct semaphore));
  child->successfullyLoaded = malloc(sizeof(bool));
  child->exitStatus = malloc(sizeof(int));
  *(child->exitStatus) = -1;
  *(child->successfullyLoaded) = true;
  /*
  int* exitStatus = (int*) malloc(sizeof(int));
  *exitStatus = -1;
  child->exitStatus = exitStatus;
  */
  /* Create a new thread to execute FILE_NAME. */
  sema_init(child->semaUpInStartProcess, 0);
  sema_init(child->semaUpInProcessExit, 0);
  child->name = fn_copy;
  struct thread *t = thread_current();
  tid = thread_create (file_name1, PRI_DEFAULT, start_process, child);
  struct thread_tid *ttid = malloc(sizeof(struct thread_tid));
  ttid->tid = tid;
  ttid->semaUpInProcessExit = child->semaUpInProcessExit;
  ttid->exitStatus = child->exitStatus;
  ttid->running = true;
 list_init(&(t->children));
 list_push_back(&(t->children), &(ttid->elem));
  sema_down(child->semaUpInStartProcess);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  if (*(child->successfullyLoaded) == false) {
	  return -1;
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *child)
{
  struct child_p *ch = (struct child_p *) child;
  char *file_name_ = ch->name;
  struct thread *t = thread_current();
  t->semaUpInProcessExit = ch->semaUpInProcessExit;
  t->exitStatus = ch->exitStatus;
  t->next_fd = 3;
  list_init(&t->files);
  log(L_TRACE, "start_process: %s", file_name_);
  log(L_TRACE, "sp, current tid: %d", thread_current()->tid);

  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  log(L_TRACE, "pre load done: %s", tokens[0]);

  success = load (tokens[0], &if_.eip, &if_.esp);

  log(L_TRACE, "Load finished calling, success: %d", success);
  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) {
	sema_up(ch->semaUpInStartProcess);
	sema_up(ch->semaUpInProcessExit);
	*(ch->successfullyLoaded) = false;
    thread_exit ();
  }
  sema_up(ch->semaUpInStartProcess);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{

  struct thread* t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->children); e != list_end (&t->children); e = list_next (e)) {
    struct thread_tid* child = list_entry(e, struct thread_tid, elem);
    if(child->tid == child_tid) { //do some cleanup
      if (child->running == true) {
        sema_down(child->semaUpInProcessExit);
        child->running = false;
        return *(child->exitStatus);
      } else {
      return -1;
      }
    }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  log(L_TRACE, "process_exit for tid: %d", thread_current()->tid);
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  struct list_elem *e;

  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
	   cur->pagedir to NULL before switching page directories,
	   so that a timer interrupt can't switch back to the
	   process page directory.  We must activate the base page
	   directory before destroying the process's page
	   directory, or our active page directory will be one
	   that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate (NULL);
    pagedir_destroy (pd);
  }
  sema_up(cur->semaUpInProcessExit);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  log(L_TRACE, "load");
  struct thread *t = thread_current ();
  log(L_TRACE, "load, current tid: %d", thread_current()->tid);
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  log(L_TRACE, "load 2: %s", file_name);

  file = filesys_open (file_name);
  log(L_TRACE, "load 2.1");

  if (file == NULL)
  {
    printf ("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
  {
    printf ("load: %s: error loading executable\n", file_name);
    goto done;
  }
  log(L_TRACE, "load 3");

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length (file))
      goto done;
    file_seek (file, file_ofs);

    if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment (&phdr, file))
        {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0)
          {
            /* Normal segment.
			   Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                          - read_bytes);
          }
          else
          {
            /* Entirely zero.
			   Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment (file, file_page, (void *) mem_page,
                             read_bytes, zero_bytes, writable))
            goto done;
        }
        else
          goto done;
            break;
    }
  }
  log(L_TRACE, "load 4");

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
	log(L_TRACE, "setup_stack completed successfully");
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

    done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
	log(L_TRACE, "Returning success from load: %d", success);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  log(L_TRACE, "validate_segment");
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  log(L_TRACE, "load_segment");
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
	   We will read PAGE_READ_BYTES bytes from FILE
	   and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page (PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
    {
      palloc_free_page (kpage);
      return false;
    }
    memset (kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page (upage, kpage, writable))
    {
      palloc_free_page (kpage);
      return false;
    }
    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

void pushArgv(void **esp) {
  *esp -= 4;
  *(char *)*esp = 0;
  int i;
  for(i = tokenCount - 1; i >= 0; i--) {
    *esp -= 4;
    *(char**)*esp = pointersToTokensOnStack[i];
  }
}

/*Place tokens on top of stack*/
void placeTokensOnStack(void **esp) {
  int i, offset;
  int len = 0;

  for(i = tokenCount - 1; i >= 0; i--) {
    offset = strlen(tokens[i]) + 1;
    *esp -= offset;
    pointersToTokensOnStack[i] = *(char**)esp;
    memcpy(*esp, tokens[i], offset);
    len += offset;
  }
	log(L_TRACE, "token character length: %d", len);
//	hex_dump((uintptr_t)*esp, *esp, sizeof(char) * len, true);
}

/* This is where we setup the stack*/
void setupStack(void **esp) {
  placeTokensOnStack(esp);
  log(L_TRACE, "setupStack, esp: %p", *esp);
  while ((*(int*)esp % 4) != 0) {*esp = *esp - 1;} //word align
  pushArgv(esp);
  *esp -= 4;
  *(char**)*esp = *esp + 4;   //push address of argv[0]
  *esp -= 4;
  *(int*)*esp = tokenCount;   //push argc
  *esp -= 4;
  *(char**)*esp = (void*) 0;
  log(L_TRACE, "*esp at end of setupStack: %p", *esp);
//  hex_dump((uintptr_t)*esp, *esp, sizeof(char) * 32, true);

}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  log(L_TRACE, "setup_stack");
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      *esp = PHYS_BASE;
      setupStack(esp); //our code
    } else {
      palloc_free_page (kpage);
    }
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  log(L_TRACE, "install_page");
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
