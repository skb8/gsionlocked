"""Private SELinux/proc file bind invariants using fake mount/FD operations."""
import os,subprocess,tempfile
from pathlib import Path
from pd2425_build import generate_services
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
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
static int failure,opened,mounted,closed[12],entry,alias_calls,alias_labels;static pid_t alias_pid;
static pid_t own_pid(void){return alias_pid;}
static int make_alias(const char *target,int parent,const char *name){assert(!strcmp(target,"self")&&parent==88&&!strcmp(name,"1234"));alias_calls++;if(failure){errno=EACCES;return -1;}return 0;}
static int alias_label(const char *path,const char *name,const void *label,size_t size,int flags){assert(!strcmp(path,"/proc/self/fd/88/1234")&&!strcmp(name,"security.selinux")&&!strcmp(label,"u:object_r:system_file:s0")&&size==sizeof("u:object_r:system_file:s0")&&!flags);alias_labels++;return 0;}
static int opening(int dir,const char *name,int flags,...){assert(dir==88&&!strcmp(name,entry?"servicemanager":"context")&&flags==(O_PATH|O_CLOEXEC|O_NOFOLLOW));opened++;if(failure==6&&opened==2){errno=ENOENT;return -1;}return opened==1?10:11;}
static int mounting(const char *from,const char *to,const char *type,unsigned long flags,const void *data){
 mounted++;assert(!type&&!data);
 if(mounted==1){assert(!strcmp(from,"/proc/self/fd/99")&&!strcmp(to,"/proc/self/fd/10")&&flags==MS_BIND);if(failure==1){errno=EPERM;return -1;}}
 else {assert(mounted==2&&!from&&!strcmp(to,"/proc/self/fd/11")&&flags==(MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|(entry?0:MS_NOEXEC)));if(failure==3){errno=EPERM;return -1;}}
 return 0;
}
static int test_stat(int fd,struct stat *out){assert(fd==99||fd==11);memset(out,0,sizeof(*out));out->st_mode=(failure==5&&fd==11?S_IFCHR:S_IFREG)|(entry?0755:0600);if(entry&&failure==10)out->st_mode|=S_ISUID;if(entry&&failure==9)out->st_uid=1000;out->st_dev=42;out->st_ino=failure==4&&fd==11?51:50;return 0;}
static int type_info(int fd,struct statfs *out){assert(fd==11);memset(out,0,sizeof(*out));out->f_type=failure==2?0xEF53:(entry?0x01021994:0xf97cff8cU);return 0;}
static int flag_info(int fd,struct statvfs *out){assert(fd==11);memset(out,0,sizeof(*out));out->f_flag=failure==8||(mounted==2&&failure!=7)?ST_RDONLY:0;if(entry&&failure==8)out->f_flag|=ST_NOEXEC;return 0;}
static int closing(int fd){assert(fd==10||fd==11);assert(!closed[fd]++);return 0;}
#define lsetxattr(...) alias_label(__VA_ARGS__)
#define getpid own_pid
#define symlinkat make_alias
#define openat(...) opening(__VA_ARGS__)
#define mount(...) mounting(__VA_ARGS__)
#define fstat(...) test_stat(__VA_ARGS__)
#define fstatfs(...) type_info(__VA_ARGS__)
#define fstatvfs(...) flag_info(__VA_ARGS__)
#define close(...) closing(__VA_ARGS__)
#define main preview_main
#include "gsi_preview.c"
#undef main
int __system_property_get(const char *key,char *value){(void)key;*value=0;return 0;}
int main(void){
 for(int n=0;n<=8;n++){
  failure=n;opened=mounted=0;memset(closed,0,sizeof(closed));
  int result=sm_bind_file(99,88,"context",n==8?0:1,SM_SELINUX_MAGIC);
  assert(n?result==-1:result==0);assert(closed[10]);
  if(n!=1&&n!=6)assert(closed[11]);
  if(n==8)assert(errno==EROFS);
  if(n==7)assert(errno==EPROTO);
 }
 failure=0;opened=mounted=0;memset(closed,0,sizeof(closed));assert(!sm_bind_file(99,88,"context",0,SM_SELINUX_MAGIC)&&mounted==1);
 alias_pid=1234;failure=0;assert(!sm_make_own_pid_alias(88)&&alias_calls==1&&alias_labels==1);failure=1;assert(sm_make_own_pid_alias(88)==-1&&errno==EACCES&&alias_calls==2);
 alias_pid=1;assert(sm_make_own_pid_alias(88)==-1&&errno==ERANGE&&alias_calls==2);alias_pid=-1;assert(sm_make_own_pid_alias(88)==-1&&alias_calls==2);
 entry=1;
 for(int n=0;n<=10;n++){
  failure=n;opened=mounted=0;memset(closed,0,sizeof(closed));
  int result=sm_bind_entry(99,88);assert(n?result==-1:result==0);assert(closed[10]);if(n!=1&&n!=6)assert(closed[11]);
  if(n==7||n==8)assert(errno==EPROTO);
 }
 return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    p=Path(temp);generate_services(p);(p/'sys').mkdir();(p/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char*,char*);\n');(p/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-I',str(p),'-I',str(ROOT/'runtime/pd2425/src'),'-I',str(ROOT/'runtime/pd2425/include'),str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True,timeout=5)
print('PASS: reopen mounted FD before readonly remount; inode/type/SELinuxFS identity, RW query exception and failed bind/flag/FD cleanup')
