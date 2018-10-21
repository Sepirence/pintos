#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
typedef int pid_t;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
int process_open(const char *file_name);
int process_filesize(int fd);
int process_read(int fd, void *buffer, unsigned size);
int process_write(int fd, void *buffer, unsigned size);
void process_seek(int fd, unsigned position);
unsigned process_tell(int fd);

struct cell
{
  int fd;
  struct file *file;
  struct list_elem elem;
};

struct process_pid
{
  int pid;
  struct list_elem elem;
};

#endif /* userprog/process.h */
