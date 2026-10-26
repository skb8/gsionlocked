"""Bounded process-local liblog callback; no Android log sockets or host logs."""
import os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
code=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
static int mode,calls,installed;static char last[1024];
static ssize_t capture(int fd,const void *bytes,size_t count){assert(fd==2&&count>0&&count<640);assert(count<sizeof(last));memcpy(last,bytes,count);last[count]=0;calls++;return (ssize_t)count;}
struct sm_log_message;
static void set_logger(void (*callback)(const struct sm_log_message*)){assert(callback);installed++;}
static void *open_library(const char *name,int flags){assert(!strcmp(name,"liblog.so")&&flags==(RTLD_NOW|RTLD_NOLOAD));return mode==1?NULL:(void*)1;}
static void *symbol(void *lib,const char *name){assert(lib==(void*)1&&!strcmp(name,"__android_log_set_logger"));return mode==2?NULL:(void*)set_logger;}
#define write capture
#define dlopen(...) open_library(__VA_ARGS__)
#define dlsym symbol
#include "service_log.h"
int main(void){
 assert(sm_enable_guest_log()==1&&installed==1);mode=1;assert(!sm_enable_guest_log());mode=2;assert(!sm_enable_guest_log()&&installed==1);
 sm_log_message message={.struct_size=sizeof(message),.priority=4,.tag="test",.message="hello"};sm_guest_logger(NULL);message.struct_size=0;sm_guest_logger(&message);message.struct_size=sizeof(message);message.priority=3;sm_guest_logger(&message);assert(!calls);
 message.priority=4;sm_guest_logger(&message);assert(calls==1&&strstr(last,"priority=4 tag=test hello\n"));
 char large[4096],tag[256];memset(large,'x',sizeof(large)-1);large[sizeof(large)-1]=0;memset(tag,'t',sizeof(tag)-1);tag[sizeof(tag)-1]=0;message.tag=tag;message.message=large;sm_guest_logger(&message);assert(calls==2&&strlen(last)<640&&last[strlen(last)-1]=='\n');
 message.tag=NULL;message.message="loop";for(int n=0;n<100;n++)sm_guest_logger(&message);assert(calls==64);
 message.priority=7;message.message="fatal after flood";for(int n=0;n<20;n++)sm_guest_logger(&message);assert(calls==72&&strstr(last,"fatal after flood"));
 assert(atomic_load(&sm_log_count)==64&&atomic_load(&sm_log_fatal_count)==8);return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);(d/'test.c').write_text(code)
    subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-I',str(ROOT/'runtime/pd2425/include'),str(d/'test.c'),'-o',str(d/'test')],check=True)
    subprocess.run([str(d/'test')],check=True,timeout=5)
print('PASS: process-local liblog setter/ABI, unavailable API, message/tag bounds, priority filter, finite log budget and reserved fatal capacity')
