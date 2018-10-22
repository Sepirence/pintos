#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static int (*syscall_inst[20]) (struct intr_frame *);
static bool is_valid_pointer(void *esp, uint8_t argc);
static bool is_valid_string(void *str);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_inst[SYS_HALT]=&syscall_halt_handler;
  syscall_inst[SYS_EXIT]=&syscall_exit_handler;
  syscall_inst[SYS_EXEC]=&syscall_exec_handler;
  syscall_inst[SYS_WAIT]=&syscall_wait_handler;
  syscall_inst[SYS_CREATE]=&syscall_create_handler;
  syscall_inst[SYS_REMOVE]=&syscall_remove_handler;
  syscall_inst[SYS_OPEN]=&syscall_open_handler;
  syscall_inst[SYS_FILESIZE]=&syscall_filesize_handler;
  syscall_inst[SYS_READ]=&syscall_read_handler;
  syscall_inst[SYS_WRITE]=&syscall_write_handler;
  syscall_inst[SYS_SEEK]=&syscall_seek_handler;
  syscall_inst[SYS_TELL]=&syscall_tell_handler;
  syscall_inst[SYS_CLOSE]=&syscall_close_handler;
}

static void
syscall_handler(struct intr_frame *f)
{
  if(!is_valid_pointer(f->esp,4))
  {
    thread_exit();
    return;
  }
  int sysnum = *(int *)f->esp;

  if(sysnum < 0 || sysnum >=20)
  {
    thread_exit();
    return;
  }
  if(syscall_inst[sysnum](f) == -1)
  {
    thread_exit();
    return;
  }
}

//SYSCALL_HALT
static void
syscall_halt(void)
{
  power_off();
}

static int
syscall_halt_handler(struct intr_frame *f UNUSED)
{
  syscall_halt();
  return 0;
}

//SYSCALL_EXIT
static void
syscall_exit(int status)
{
  thread_exit();
}

static int
syscall_exit_handler(struct intr_frame *f)
{
  int status;
  if(is_valid_pointer(f->esp + 4, 4))
    status = *((int *)f->esp + 1);
  else
    return -1;
  syscall_exit(status);
  return 0;
}

//SYSCALL_EXEC
static pid_t
syscall_exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

static int
syscall_exec_handler(struct intr_frame *f)
{
  if(!is_valid_pointer(f->esp+4,4)||!is_valid_string(*(char**)(f->esp+4)))
    return -1;
  char *cmd_line = *(char**)(f->esp+4);
  if(strlen(cmd_line)> PGSIZE)
  {
    return -1;
  }
  if(strlen(cmd_line) == 0 || cmd_line[0]==' ')
  {
    return -1;
  }
  f->eax = syscall_exec(cmd_line);
  return 0;
}

//SYSCALL_WAIT
static int
syscall_wait(pid_t pid)
{
  return process_wait(pid);
}

static int
syscall_wait_handler(struct intr_frame *f)
{
  pid_t pid;
  if(is_valid_pointer(f->esp+4,4))
    pid = *((int*)f->esp+1);
  else
    return -1;
  f->eax = syscall_wait(pid);
  return 0;
}

//SYSCALL_CREATE
static bool
syscall_create(const char *file, unsigned initial_size)
{
  return filesys_create(file,initial_size);
}

static int
syscall_create_handler(struct intr_frame *f)
{
  if(is_valid_pointer(f->esp+4,4)&&is_valid_pointer(f->esp+8,4)&&is_valid_string(*(char**)(f->esp+4)))
  {
    char *file = *(char**)(f->esp+4);
    unsigned initial_size = *(int *)(f->esp+4);
    f->eax = syscall_create(file,initial_size);
    return 0;
  }
}

//SYSCALL_REMOVE
static bool
syscall_remove(const char *file)
{
  return filesys_remove(file);
}

static int
syscall_remove_handler(struct intr_frame *f)
{
  if(is_valid_pointer(f->esp+4,4)&&is_valid_string(*(char**)(f->esp+4)))
  {
    char *file = *(char**)(f->esp+4);
    f->eax = syscall_remove(file);
    return 0;
  }
}

//SYSCALL_OPEN
static int
syscall_open(const char *file)
{
  return process_open(file);
}

static int
syscall_open_handler(struct intr_frame *f)
{
  if(is_valid_pointer(f->esp+4,4)&&is_valid_string(*(char**)(f->esp+4)))
  {
    char *file = *(char**)(f->esp+4);
    f->eax = syscall_open(file);
    return 0;
  }
}

//SYSCALL_FILESIZE
static int
syscall_filesize(int fd)
{
  return process_filesize(fd);
}

static int
syscall_filesize_handler(struct intr_frame *f)
{
  if(!is_valid_pointer(f->esp+4,4))
    return -1;
  int fd = *(int *)(f->esp+4);
  f->eax = syscall_filesize(fd);
  return 0;
}

//SYSCALL_READ
static int
syscall_read(int fd, void *buffer, unsigned size)
{
  return process_read(fd,buffer,size);
}

static int
syscall_read_handler(struct intr_frame *f)
{
  if(!is_valid_pointer(f->esp+4,12))
    return -1;
  int fd = *(int*)(f->esp+4);
  void *buffer = *(char**)(f->esp+8);
  unsigned size = *(unsigned*)(f->esp+12);
  if(is_valid_pointer(buffer,1)&&is_valid_pointer(buffer+size,1))
  {
    f->eax = syscall_read(fd,buffer,size);
    return 0;
  }
  else
    return -1;
}

//SYSCALL_WRITE
static int
syscall_write(int fd, const void *buffer, unsigned size)
{
  return process_write(fd,buffer,size);
}

static int
syscall_write_handler(struct intr_frame *f)
{
  if(!is_valid_pointer(f->esp+4,12))
    return -1;
  int fd = *(int*)(f->esp+4);
  void *buffer = *(char**)(f->esp+8);
  unsigned size = *(unsigned*)(f->esp+12);
  if(is_valid_pointer(buffer,1)&&is_valid_pointer(buffer+size,1))
  {
    f->eax = syscall_write(fd,buffer,size);
    return 0;
  }
  else
    return -1;
}

//SYSCALL_SEEK
static void
syscall_seek(int fd, unsigned position)
{
  process_seek(fd,position);
}

static int
syscall_seek_handler(struct intr_frame *f)
{
  if(!is_valid_pointer(f->esp+4,8))
    return -1;
  int fd = *(int*)(f->esp+4);
  unsigned pos = *(unsigned *)(f->esp+8);
  syscall_seek(fd,pos);
  return 0;
}

//SYSCALL_TELL
static unsigned
syscall_tell(int fd)
{
  return process_tell(fd);
}

static int
syscall_tell_handler(struct intr_frame *f)
{
  if(!is_valid_pointer(f->esp+4,4))
    return -1;
  int fd = *(int*)(f->esp+4);
  f->eax = syscall_tell(fd);
  return 0;
}

//SYSCALL_CLOSE
static void
syscall_close(int fd)
{
  process_close(fd);
}

static int
syscall_close_handler(struct intr_frame *f)
{
  if(!is_valid_pointer(f->esp+4,4))
    return -1;
  int fd = *(int*)(f->esp+4);
  syscall_close(fd);
  return 0;
}

//HELPER FUNCTIONS
static int
get_user(const uint8_t *addr)
{
  if(!is_user_vaddr(addr))
    return -1;
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*addr));
  return result;
}

static bool
is_valid_pointer(void *esp, uint8_t argc)
{
  uint8_t i;

  for(i=0;i<argc;i++)
  {
    if(get_user(((uint8_t*)esp)+i) == -1)
      return false;
  }
  return true;
}

static bool
is_valid_string(void *str)
{
  int check = -1;
  while((check = get_user((uint8_t*)str++))!='\0' && check != -1);
  if(check = '\0')
    return true;
  else
    return false;
}
