"""Reject false policy/identity views before the private ART test (mock APIs)."""
import os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <android/dlext.h>
static int failure,located,queried,namespaces;static jmp_buf escape;
static uid_t identity(void){return failure==1?1001:1000;}
static int state(int option,...){if(option==PR_GET_NO_NEW_PRIVS)return failure==2?0:1;assert(option==PR_GET_SECCOMP);return failure==3?1:2;}
static int fs_type(const char *path,struct statfs *out){assert(!strcmp(path,"/sys/fs/selinux"));memset(out,0,sizeof(*out));out->f_type=failure==4?0xEF53:0xf97cff8cU;return 0;}
static int test_flags(const char *path,struct statvfs *out){assert(!strcmp(path,"/sys/fs/selinux"));memset(out,0,sizeof(*out));out->f_flag=failure==5?0:ST_RDONLY;return 0;}
static void mount_pointer(const char *path){assert(!strcmp(path,"/sys/fs/selinux"));located++;}
static int enabled(void){assert(located);queried++;return failure==8?0:1;}
static int enforcing(void){assert(located);queried++;return failure==9?0:1;}
static int context(char **out){if(failure==11)return -1;*out=strdup(failure==10?"u:r:init:s0":"u:r:ksu:s0");return 0;}
static void release_context(char *out){free(out);}
static void *library(const char *name,int mode){assert(!strcmp(name,"libselinux.so")&&mode==(RTLD_NOW|RTLD_LOCAL));return failure==6?NULL:(void*)1;}
static struct android_namespace_t *namespace_by_name(const char *name){return !strcmp(name,"system")?(void*)2:NULL;}
static void *extended(const char *name,int mode,const android_dlextinfo *ext){assert(!strcmp(name,"libselinux.so")&&mode==RTLD_NOW&&ext->flags==ANDROID_DLEXT_USE_NAMESPACE&&ext->library_namespace==(void*)2);return (void*)1;}
static void *symbol(void *lib,const char *name){if(!strcmp(name,"android_get_exported_namespace")){assert(lib==RTLD_DEFAULT);return namespaces?(void*)namespace_by_name:NULL;}assert(lib==(void*)1);if(!strcmp(name,"set_selinuxmnt"))return (void*)mount_pointer;if(!strcmp(name,"is_selinux_enabled"))return (void*)enabled;if(!strcmp(name,"security_getenforce"))return (void*)enforcing;if(!strcmp(name,"getcon"))return failure==7?NULL:(void*)context;if(!strcmp(name,"freecon"))return (void*)release_context;assert(0);return NULL;}
static int logging(int fd,const char *format,...){assert(fd==2);(void)format;return 0;}
static _Noreturn void exiting(int status){assert(status==124);longjmp(escape,1);}
#define getuid identity
#define geteuid identity
#define getgid identity
#define getegid identity
#define prctl state
#define statfs(...) fs_type(__VA_ARGS__)
#define statvfs(...) test_flags(__VA_ARGS__)
#define dlopen library
#define dlsym symbol
#define android_dlopen_ext extended
#define dprintf logging
#define _exit exiting
#define __attribute__(value)
#include "apex_selinux.c"
int main(void){for(namespaces=0;namespaces<2;namespaces++)for(volatile int n=0;n<=11;n++){failure=n;located=queried=0;if(!setjmp(escape)){begin();assert(!n&&located==(namespaces?2:1)&&queried==2*located);}else{assert(n);if(n<6)assert(!located&&!queried);}}return 0;}
'''
with tempfile.TemporaryDirectory() as temp:
 d=Path(temp);(d/'android').mkdir();(d/'android/dlext.h').write_text('#pragma once\n#include <stdint.h>\nstruct android_namespace_t;\ntypedef struct {uint64_t flags;struct android_namespace_t *library_namespace;} android_dlextinfo;\n#define ANDROID_DLEXT_USE_NAMESPACE 512\n')
 (d/'test.c').write_text(source)
 subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-I',str(d),'-I',str(ROOT/'runtime/pd2425/src'),str(d/'test.c'),'-o',str(d/'test')],check=True);subprocess.run([str(d/'test')],check=True,timeout=5)
print('PASS: actual libselinux calls required; wrong identity/NNP/filter/filesystem/readonly/enforcing/domain/symbols refused; exported namespace copies checked')
