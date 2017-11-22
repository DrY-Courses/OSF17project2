#ifndef OSF17PROJECT_TACOS_FRAME_H
#define OSF17PROJECT_TACOS_FRAME_H

#include <hash.h>
#include "vm/page.h"
#include "vm/swap.h"

struct frame {
    void*   kernel_addr;			/* Physical address of the page */
    void*   user_vaddr;			/* User virtual address of the page*/
    struct  thread *thread;		/* Thread the page belongs to*/
    struct  data_origin *origin;/* Source of origin*/
    bool    pinned;				/* Pin - makes the page not evictable */

    struct  hash_elem hash_elem;
};

void  frame_init (void);
void  frame_evict (void);
void* frame_get (void*, bool, struct origin_info*);
bool  frame_free (void*);
struct frame* frame_find (void*);


/* Frames security functions */
void frame_pin (void*, int);
void frame_unpin (void*, int);
void frame_kernel_pin (void*, int);
void frame_kernel_unpin (void*, int);
void lock_frames (void);
void unlock_frames (void);

#endif //OSF17PROJECT_TACOS_FRAME_H
