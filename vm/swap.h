#ifndef OSF17PROJECT_TACOS_SWAP_H
#define OSF17PROJECT_TACOS_SWAP_H

#include "vm/frame.h"
#include "devices/block.h"

struct swap_slot{
    struct frame* frame;		/* Frame from a frame table */
    block_sector_t swap_addr;	/* Address of the first segment where the page is stored */
    struct hash_elem hash_elem;
};

void swap_init (void);                      /* Initialize swap */
void swap_load (void* , struct swap_slot*);  /* Load swap */
void swap_store (struct swap_slot*);        /* Store swap */
void swap_free (struct swap_slot*);         /* Free the swap slot */

struct swap_slot* swap_loc(struct frame*);  /* Swap the slot */


#endif //OSF17PROJECT_TACOS_SWAP_H
