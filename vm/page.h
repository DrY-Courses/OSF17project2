#ifndef OSF17PROJECT_TACOS_PAGE_H
#define OSF17PROJECT_TACOS_PAGE_H

enum page_type
{
    FILE,
    SWAP,
    EXEC,
    ZERO
};

struct page
{
    enum page_type      page_t;     /* What type of page are we looking at */
    struct data_origin* origin;     /* Original location in file system */
    struct swap_slot*   swap_elem;  /* Location in swap */
};

struct data_origin
{
    struct file*   source_file;
    bool           writable;
    enum page_type page_t;
    off_t          offset;
    size_t         zero_size;
};

struct page* new_file_page (struct file*, off_t, size_t, bool, enum page_type);
struct page* new_swap_page (struct swap_slot*);
struct page* new_zero_page (void);
inline bool is_stack_access(void* , void *);

#endif //OSF17PROJECT_TACOS_PAGE_H
