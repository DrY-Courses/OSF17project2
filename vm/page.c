#include "vm/page.h"
#include "threads/malloc.h"

#define INSUFFICIENT_MEMORY "Insufficient Memory"

struct page*
new_zero_page ()
{
    struct page* new_page = (struct page*) malloc(sizeof(struct page));

    if(new_page == NULL)
    {
        PANIC(INSUFFICIENT_MEMORY);
    }

    new_page->page_t = ZERO;
    new_page->origin = NULL;
    new_page->swap_elem = NULL;

    return new_page;
}

struct page*
new_file_page (struct file* source, off_t offset, size_t zero_after, bool writable, enum page_type page_t)
{
    struct page *new_page = (struct page*) malloc(sizeof(struct page));

    if(new_page == NULL)
    {
        PANIC(INSUFFICIENT_MEMORY);
    }

    new_page->page_t = page_t;

    struct data_origin *origin = (struct data_origin*) malloc (sizeof(struct data_origin));

    if(origin == NULL)
    {
        PANIC(INSUFFICIENT_MEMORY);
    }

    origin->source_file = source;
    origin->offset = offset;
    origin->zero_size = zero_after;
    origin->writable = writable;
    origin->page_t = page_t;

    new_page->origin = origin;
    new_page->swap_elem = NULL;

    return new_page;
}

struct page*
new_swap_page (struct swap_slt* swap_location)
{
    struct page *new_page = (struct page*) malloc (sizeof(struct page));
    if(new_page == NULL)
    {
        PANIC(INSUFFICIENT_MEMORY);
    }
    new_page->location = SWAP;
    new_page->origin = NULL;
    new_page->swap_elem = swap_location;
    return new_page;
}

inline bool
is_stack_access (void* esp, void* address)
{
    return (address < PHYS_BASE) && (address > STACK_BOTTOM) && (address + 32 >= esp);
}