#include "vm/frame.h"
#include <stdio.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

static struct hash frames;
static struct lock frames_lock;

static bool DEBUG = false;

void lock_frames(void);
void unlock_frames(void);
bool frame_less(const struct hash_elem*, const struct hash_elem*, void*);
unsigned frame_hash(const struct hash_elem*, void*);
void page_dump(struct frame*);
void frame_set_pin(void*, bool);
int get_page_class(uint32_t* , const void*);

void
lock_frames()
{
    lock_acquire(&frames_lock);
}

void unlock_frames()
{
    lock_release(&frames_lock);
}

void
frame_init()
{
    hash_init(&frames, frame_hash, frame_less, NULL);
    lock_init(&frames_lock);
}

/*
Allocates a new page, and adds it to the frame table
*/
void*
frame_get(void* user_page, bool zero, struct origin_info*origin)
{
    void* kernel_page = palloc_get_page(PAL_USER |(zero ? PAL_ZERO : 0));
    struct thread* t = thread_current();

    /* There is no more free memory, we need to free some*/
    if(kernel_page == NULL)
    {
        lock_frames();
        evict();
        kernel_page = palloc_get_page(PAL_USER |(zero ? PAL_ZERO : 0));
        unlock_frames();
    }

    if(kernel_page != NULL)
    {
        struct frame* frame =(struct frame*) malloc(sizeof(struct frame));
        frame -> addr = kernel_page;
        frame -> user_page = user_page;
        frame -> origin = origin;
        frame -> thread = t;
        frame -> pinned = false;

        lock_frames();
        hash_insert(&frames, &frame -> hash_elem);
        unlock_frames();
    }

    return kernel_page;
}

/*
Remove a frame, and clean up after it.
*/
bool
frame_free(void* addr)
{
    struct frame* frame;
    struct hash_elem* found_frame;
    struct frame frame_elem;
    frame_elem.addr = addr;

    found_frame = hash_find(&frames, &frame_elem.hash_elem);
    if(found_frame != NULL)
    {
        frame = hash_entry(found_frame, struct frame, hash_elem);

        palloc_free_page(frame->addr); //Free physical memory
        hash_delete(&frames, &frame->hash_elem); //Free entry in the frame table
        free(frame); //Delete the structure

        return true;
    } else {
        return false;
    }
}

/*
Sets frame's pin to the given value
*/
void
frame_set_pin(void* kernel_page, bool pinval)
{
    struct frame* frame = frame_find(kernel_page);
    if(frame == NULL)
    {
        return;
    }
    frame->pinned = pinval;
}

/*
Pins a frame using user virtual memory address
*/
void
frame_pin(void* vaddr, int l)
{
    struct thread* t = thread_current();
    int it = l / PGSIZE;
    if(l % PGSIZE) it++;

    int i;
    for(i = 0; i < it; i++)
    {
        sema_down(&t->pagedir_mod);
        void* kernel_page = pagedir_get_page(t->pagedir, pg_round_down(vaddr) + i* PGSIZE);
        sema_up(&t->pagedir_mod);
        if(kernel_page == 0 || pg_ofs(kernel_page) != 0) return;
        frame_set_pin(kernel_page, true);
    }
}

/* Unpins a frame using user virtual memory address*/
void
frame_unpin(void* vaddr, int l)
{
    struct thread* t = thread_current();
    int it = l / PGSIZE;
    if(l % PGSIZE) it++;

    int i;
    for(i = 0; i < it; i++)
    {
        sema_down(&t->pagedir_mod);
        void* kernel_page = pagedir_get_page(t->pagedir, pg_round_down(vaddr) + i* PGSIZE);
        sema_up(&t->pagedir_mod);
        if(kernel_page == 0 || pg_ofs(kernel_page) != 0)  return;
        frame_set_pin(kernel_page, false);
    }
}

/* Pins a frame using physical memory address*/
void
frame_pin_kernel(void* kernel_page, int l)
{
    int it = l / PGSIZE;
    if(l % PGSIZE) it++;

    int i;
    for(i = 0; i < it; i++)
    {
        if(kernel_page == 0 || pg_ofs(kernel_page) != 0) return;
        frame_set_pin(kernel_page, true);
    }
}

/* Unpins a frame using physical memory address*/
void
frame_unpin_kernel(void* kernel_page, int l)
{
    int it = l / PGSIZE;
    if(l % PGSIZE) it++;

    int i;
    for(i = 0; i < it; i++)
    {
        if(kernel_page == 0 || pg_ofs(kernel_page) != 0) return;
        frame_set_pin(kernel_page, false);
    }
}

/* Looks for a frame with the given physical address, if no such frame exists return NULL*/
struct frame*
frame_find(void* addr)
{
    struct frame* frame;
    struct hash_elem* found_frame;
    struct frame frame_elem;
    frame_elem.addr = addr;

    found_frame = hash_find(&frames, &frame_elem.hash_elem);
    if(found_frame != NULL)
    {
        frame = hash_entry(found_frame, struct frame, hash_elem);
        return frame;
    } else {
        return NULL;
    }
}

/* Comparision function*/
bool
frame_less(const struct hash_elem*a_, const struct hash_elem*b_	, void*aux UNUSED)
{
    const struct frame* a = hash_entry(a_, struct frame, hash_elem);
    const struct frame* b = hash_entry(b_, struct frame, hash_elem);
    return a->addr < b->addr;
}

/* Hash function*/
unsigned
frame_hash(const struct hash_elem*fe, void*aux UNUSED)
{
    const struct frame* frame = hash_entry(fe, struct frame, hash_elem);
    return hash_int((unsigned)frame->addr);
}


/* Determines a class the page belongs to*/
int
get_page_class(uint32_t* pd, const void* page) {
    void* kernel_page = pagedir_get_page(pd, page);
    if(kernel_page == NULL) return -1;

    bool dirty = pagedir_is_dirty(pd, page);
    bool accessed = pagedir_is_accessed(pd, page);

    return(accessed) ?((dirty) ? 4 : 2) :((dirty) ? 3 : 1);
}


/*
Performs actual eviction of a page.
*/
void
page_dump(struct frame* frame)
{
    bool dirty = pagedir_is_dirty(frame->thread->pagedir, frame->user_page);
    struct suppl_page* suppl_page = NULL;

    if(dirty)
    {
        if(frame->origin != NULL && frame->origin->location == FILE)
        {
            filesys_lock_acquire();
            frame_pin(frame->user_page, PGSIZE);
            file_write_at(frame->origin->source_file, frame->addr, frame->origin->zero_after, frame->origin->offset);
            frame_unpin(frame->user_page, PGSIZE);
            filesys_lock_release();

            suppl_page = new_file_page(frame->origin->source_file, frame->origin->offset, frame->origin->zero_after, frame->origin->writable, FILE);
        } else {
            struct swap_slt* swap_el = swap_slot(frame);

            frame_pin(frame->user_page, PGSIZE);
            swap_store(swap_el);
            frame_unpin(frame->user_page, PGSIZE);

            suppl_page = new_swap_page(swap_el);
        }
    }
    else
    {
        if(frame->origin != NULL)
        {
            suppl_page = new_file_page(frame->origin->source_file, frame->origin->offset, frame->origin->zero_after, frame->origin->writable, frame->origin->location);
        } else {
            suppl_page = new_zero_page();
        }
    }

    sema_down(&frame->thread->pagedir_mod);
    pagedir_clear_page(frame->thread->pagedir, frame->user_page);
    pagedir_set_page_suppl(frame->thread->pagedir, frame->user_page, suppl_page);
    sema_up(&frame->thread->pagedir_mod);

}

/* Selects a frame to evict*/
void
evict()
{
    struct hash_iterator it;
    void* kernel_page = NULL;
    struct frame*f = NULL;

    int i;
    for(i = 0; i < 2 && kernel_page == NULL; i++)
    {
        hash_first(&it, &frames);

        /* Look for an element in the lowest page_class*/
        while(kernel_page == NULL && hash_next(&it))
        {
            f = hash_entry(hash_cur(&it), struct frame, hash_elem);
            if(f->pinned) continue;
            
            sema_down(&f->thread->pagedir_mod);
            int page_class = get_page_class(f->thread->pagedir, f->user_page);
            sema_up(&f->thread->pagedir_mod);
            
            if(page_class == 1)
            {
                page_dump(f);
                kernel_page = f->addr;
            }
        }

        hash_first(&it, &frames);

        /* Look for an element in the higher page_class, at the same time lowering page_classes of passed elements*/
        while(kernel_page == NULL && hash_next(&it))
        {
            f = hash_entry(hash_cur(&it), struct frame, hash_elem);
            if(f->pinned) continue;
           
            sema_down(&f->thread->pagedir_mod);
            int page_class = get_page_class(f->thread->pagedir, f->user_page);
            sema_up(&f->thread->pagedir_mod);
           
            if(page_class == 3)
            {
                page_dump(f);
                kernel_page = f->addr;
            } else if(page_class > 0)
            {
                pagedir_set_accessed(f->thread->pagedir, f->user_page, false);
            }
        }
    }

    palloc_free_page(f->addr); /* Free physical memory*/
    hash_delete(&frames, &f->hash_elem); /* Free entry in the frame table*/
    free(f); /* Delete the structure*/
}