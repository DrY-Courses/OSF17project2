#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void syscall_init (void);

void sys_halt(void);

void sys_exit(int status);

int sys_exec(char *cmd_line);

int sys_wait(int pid);

bool sys_create(char *file, int initial_size);

bool sys_remove(char *file);

int sys_open(char *file);

int sys_filesize(int fd);

int sys_read(int fd, void *buffer, int size);

int sys_write(int fd, void *buffer, unsigned size);

void sys_seek(int fd, int position);

int sys_tell(int fd);

void sys_close(int fd);

#endif /* userprog/syscall.h */
