#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);


static int syscall_halt_handler(struct intr_frame *f);
static int syscall_exit_handler(struct intr_frame *f);
static int syscall_exec_handler(struct intr_frame *f);
static int syscall_wait_handler(struct intr_frame *f);
static int syscall_create_handler(struct intr_frame *f);
static int syscall_remove_handler(struct intr_frame *f);
static int syscall_open_handler(struct intr_frame *f);
static int syscall_filesize_handler(struct intr_frame *f);
static int syscall_read_handler(struct intr_frame *f);
static int syscall_write_handler(struct intr_frame *f);
static int syscall_seek_handler(struct intr_frame *f);
static int syscall_tell_handler(struct intr_frame *f);
static int syscall_close_handler(struct intr_frame *f);




#endif /* userprog/syscall.h */
