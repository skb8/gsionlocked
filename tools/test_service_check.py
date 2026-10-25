"""Preload guards with mocked identity/kernel policy; never loads host SELinux."""
import os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <linux/android/binder.h>
#include <linux/magic.h>
#include <dlfcn.h>
static int failure,queried,located,opened;static jmp_buf escape;static char message[512];
static uid_t identity(void){return failure==1?1001:1000;}
static int state(int option,...){if(option==PR_GET_NO_NEW_PRIVS)return failure==2?0:1;assert(option==PR_GET_SECCOMP);return 2;}
static int test_fs(const char *path,struct statfs *out){(void)path;memset(out,0,sizeof(*out));out->f_type=failure==3?0xEF53:0xf97cff8cU;return 0;}
static int test_flags(const char *path,struct statvfs *out){memset(out,0,sizeof(*out));out->f_flag=failure==4&&!strcmp(path,"/sys/fs/selinux/load")?0:ST_RDONLY;return 0;}
static void *library_fn(const char *name,int flag){assert(!strcmp(name,"libselinux.so")&&flag==(RTLD_NOW|RTLD_LOCAL));return (void*)1;}
static void set_mount(const char *path){assert(!strcmp(path,"/sys/fs/selinux"));located=1;}
static int enabled(void){return failure==10?0:1;}
static int enforce(void){assert(located);return failure==5?0:1;}
static int context(char **out){*out=failure==6?"u:r:ksu:s0":"u:r:servicemanager:s0";return 0;}
static void release_context(char *c){assert(c&&!strcmp(c,"u:r:servicemanager:s0"));}
static int decision(const char *from,const char *to,const char *class_name,const char *permission,void *aux){assert(!strcmp(from,"u:r:servicemanager:s0")&&!strcmp(to,"u:object_r:servicemanager_service:s0")&&!strcmp(class_name,"service_manager")&&!strcmp(permission,"add")&&!aux);queried=1;return failure==7?-1:0;}
static void *symbol(void *lib,const char *name){assert(lib==(void*)1);if(!strcmp(name,"set_selinuxmnt"))return (void*)set_mount;if(!strcmp(name,"is_selinux_enabled"))return (void*)enabled;if(!strcmp(name,"security_getenforce"))return (void*)enforce;if(!strcmp(name,"getcon"))return (void*)context;if(!strcmp(name,"freecon"))return (void*)release_context;if(!strcmp(name,"selinux_check_access"))return (void*)decision;assert(0);return NULL;}
static int opening(const char *path,int flag,...){
 if(!strcmp(path,"/sys/fs/selinux/class/service_manager/index"))return 11;
 if(!strcmp(path,"/sys/fs/selinux/class/service_manager/perms/add"))return 12;
 if(!strcmp(path,"/sys/fs/selinux/access")){assert(flag==(O_RDWR|O_CLOEXEC|O_NOFOLLOW));return 13;}
 assert(queried&&!strcmp(path,"/dev/binder")&&flag==(O_RDWR|O_CLOEXEC));opened=1;return 10;
}
static ssize_t reading(int fd,void *buffer,size_t count){
 const char *text=fd==11?"42":fd==12?"1":failure==11?"0 ffffffff 0 0 1 0":failure==12?"1 ffffffff 0 0 1 1":failure==13?"garbage":failure==14?"1 ffffffff 0 0 1 0 extra":"1 ffffffff 0 0 1 0";
 assert(fd>=11&&fd<=13&&strlen(text)<count);memcpy(buffer,text,strlen(text));return (ssize_t)strlen(text);
}
static int fd_fs(int fd,struct statfs *out){assert(fd==10);memset(out,0,sizeof(*out));out->f_type=failure==8?0xEF53:BINDERFS_SUPER_MAGIC;return 0;}
static int query(int fd,unsigned long request,...){assert(fd==10&&request==BINDER_VERSION);va_list a;va_start(a,request);struct binder_version *v=va_arg(a,struct binder_version*);va_end(a);v->protocol_version=failure==9?7:BINDER_CURRENT_PROTOCOL_VERSION;return 0;}
static int closing(int fd){assert(fd>=10&&fd<=13);return 0;}
static ssize_t writing(int fd,const void *text,size_t size){if(fd==13){assert(strstr(text,"u:r:servicemanager:s0 u:object_r:servicemanager_service:s0 42"));return (ssize_t)size;}assert(size<sizeof(message));memcpy(message,text,size);message[size]=0;return (ssize_t)size;}
static _Noreturn void exiting(int code){assert(code==124);longjmp(escape,1);}
#define getuid identity
#define geteuid identity
#define getgid identity
#define getegid identity
#define prctl state
#define statfs(...) test_fs(__VA_ARGS__)
#define statvfs(...) test_flags(__VA_ARGS__)
#define dlopen(...) library_fn(__VA_ARGS__)
#define dlsym symbol
#define open opening
#define fstatfs fd_fs
#define ioctl query
#define close closing
#define read reading
#define write writing
#define _exit exiting
#define __attribute__(value)
#include "service_check.c"
int main(void){
 for(volatile int n=0;n<=14;n++){
  failure=n;queried=located=opened=0;message[0]=0;
  if(!setjmp(escape)){sm_check();assert(!n&&!strcmp(message,"PD2425_SM_ENV_OK\n")&&queried&&opened);}
  else {assert(n&&strstr(message,"PD2425_SM_ENV_FAIL"));if(n<5)assert(!located);if(n<7||n==10)assert(!queried);if(n<8||n>=10)assert(!opened);}
 }
 return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    p=Path(temp);(p/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-I',str(ROOT/'runtime/pd2425/src'),str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True,timeout=5)
print('PASS: real-policy call required; wrong UID/domain/enforcing, writable policy view, wrong BinderFS/protocol cannot enter service main (mock APIs)')
