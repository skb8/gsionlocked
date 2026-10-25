"""Private config creation, mount flags and failure cleanup using a mock kernel."""
import os, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <linux/openat2.h>
static int failure,opens,mounts,files,closed[20],interrupted;
static size_t bytes;
static long call(long number,...){
 assert(number==SYS_openat2);va_list a;va_start(a,number);int root=va_arg(a,int);const char *name=va_arg(a,const char*);struct open_how *h=va_arg(a,struct open_how*);va_end(a);
 assert(root==4&&!strcmp(name,"linkerconfig")&&h->resolve==(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS));
 if(failure==1){errno=ELOOP;return -1;}return 10+opens++;
}
static int mounting(const char *src,const char *dst,const char *type,unsigned long flags,const void *data){
 mounts++;
 if(mounts==1){assert(!strcmp(src,"tmpfs")&&!strcmp(type,"tmpfs")&&!strcmp(dst,"/proc/self/fd/10")&&!strcmp(data,"size=64k,mode=0755"));assert(flags==(MS_NOSUID|MS_NODEV|MS_NOEXEC));}
 else {assert(!src&&!type&&!data&&!strcmp(dst,"/proc/self/fd/11"));assert(flags==(MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));}
 if((failure==2&&mounts==1)||(failure==5&&mounts==2)){errno=EPERM;return -1;}return 0;
}
static int opening(int dir,const char *name,int flags,...){
 assert(dir==11&&!strcmp(name,"ld.config.txt")&&(flags&O_NOFOLLOW));files++;
 if(files==1){assert((flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL));if(failure==3){errno=EACCES;return -1;}return 12;}
 if(failure==7)return 13;
 errno=EROFS;return -1;
}
static ssize_t writing(int fd,const void *data,size_t size){
 assert(fd==12&&data&&size);if(failure==4){errno=EIO;return -1;}
 if(!interrupted++){errno=EINTR;return -1;}size_t n=size>7?7:size;bytes+=n;return (ssize_t)n;
}
static int status(int dir,struct statvfs *fs){assert(dir==11);memset(fs,0,sizeof(*fs));fs->f_flag=failure==6?0:ST_RDONLY;return 0;}
static int closing(int fd){assert(fd>=10&&fd<=13);assert(!closed[fd]++);return 0;}
#define syscall call
#define mount mounting
#define openat opening
#define write writing
#define fstatvfs status
#define close closing
#include "preview_linkerconfig.h"
#undef syscall
#undef mount
#undef openat
#undef write
#undef fstatvfs
#undef close
int main(void){
 for(int test=0;test<=7;test++){
  failure=test;opens=mounts=files=interrupted=0;bytes=0;memset(closed,0,sizeof(closed));
  int result=pv_create_linkerconfig(4);assert(test?result==-1:result==0);
  if(!test)assert(bytes==sizeof(pv_bootstrap_config)-1&&mounts==2&&files==2);
  if(opens>0)assert(closed[10]);
  if(opens>1)assert(closed[11]);
  if(files>0&&test!=3)assert(closed[12]);
  if(test==7)assert(closed[13]);
 }
 return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    p=Path(temp);(p/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-I',str(ROOT/'runtime/pd2425/include'),str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True,timeout=5)
print('PASS: IN_ROOT/NO_SYMLINKS, exclusive config, partial/EINTR writes, readonly/noexec remount, actual write rejection and failure FD cleanup (mock kernel)')
