#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

#include <bitmap.h>
#include <hash.h>
#include <debug.h>
#include <stdio.h>

static struct block* swap;      /* swap block  */
static struct lock   swap_lock; /* lock for swap */
unsigned             swap_size; /* size of swap */

static struct bitmap * free_swap_bitmap; /* free swap slots */

block_sector_t find_free_swap(void);

/* Swap slot constructor */
struct swap_slot* swap_slot(struct frame* frame)
{
    struct swap_slot* slot = malloc(sizeof(struct swap_slot));
    slot->frame = frame;
    return slot;
}

/* Returns first address on the swap where we can store a page of memory */
block_sector_t
swap_find_free ()
{
    bool full = bitmap_all(free_swap_bitmap, 0, swap_size);
    if(!full){
        block_sector_t first_free = bitmap_scan_and_flip(free_swap_bitmap, 0, PGSIZE/BLOCK_SECTOR_SIZE, false);
        return first_free;
    } else {
        PANIC("Memory exhausted: Swap is full");
    }
}

/* Initialize the swap */
void swap_init(){
    swap = block_get_role (BLOCK_SWAP);
    swap_size = block_size (swap);
    lock_init (&swap_lock);
    free_swap_bitmap = bitmap_create (swap_size);
}

/* Loads a page from swap to the memory */
void
swap_load (void *addr, struct swap_slot* slot)
{
    lock_acquire (&swap_lock);

    int i;
    for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++){
        block_read(swap, slot->swap_addr + i, addr + i * BLOCK_SECTOR_SIZE);
    }

    bitmap_set_multiple (free_swap_bitmap, slot->swap_addr, PGSIZE/BLOCK_SECTOR_SIZE, false);
    lock_release (&swap_lock);
}

/* Stores a page from memory on the swap */
void
swap_store (struct swap_slot* slot)
{
    lock_acquire (&swap_lock);
    block_sector_t swap_addr = find_free_swap();

    int i;
    for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++){
        block_write (swap, swap_addr + i, slot->frame->addr + i * BLOCK_SECTOR_SIZE);
    }

    slot->swap_addr = swap_addr;
    lock_release (&swap_lock);
}


/* Frees a swap slot */
void
swap_free(struct swap_slot* slot)
{
    lock_acquire (&swap_lock);
    bitmap_set_multiple (free_swap_bitmap, slot->swap_addr, PGSIZE / BLOCK_SECTOR_SIZE, false);
    lock_release (&swap_lock);
}

