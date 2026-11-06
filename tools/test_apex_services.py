"""Exercise owned-process cleanup and private ready-property authentication."""
import os, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source=r'''
#define _GNU_SOURCE
#include "apex_service_protocol.h"
#include <assert.h>
#include <fcntl.h>
static pid_t child(void){pid_t pid=fork();assert(pid>=0);if(!pid)for(;;)pause();return pid;}
int main(void){
 pid_t owned[]={1234,1235};
 assert(as_ready_sender(1234,1000,1000,0x20001,"servicemanager.ready","true",owned)==0);
 assert(as_ready_sender(1235,1000,1000,0x20001,"hwservicemanager.ready","true",owned)==1);
 assert(as_ready_sender(1235,1000,1000,0x20001,"servicemanager.ready","true",owned)==-1);
 assert(as_ready_sender(1234,1000,1000,0x20001,"hwservicemanager.ready","true",owned)==-1);
 assert(as_ready_sender(1236,1000,1000,0x20001,"servicemanager.ready","true",owned)==-1);
 assert(as_ready_sender(1234,0,1000,0x20001,"servicemanager.ready","true",owned)==-1);
 assert(as_ready_sender(1234,1000,0,0x20001,"servicemanager.ready","true",owned)==-1);
 assert(as_ready_sender(1234,1000,1000,0x20000,"servicemanager.ready","true",owned)==-1);
 assert(as_ready_sender(1234,1000,1000,0x20001,"servicemanager.ready","false",owned)==-1);
 assert(as_ready_sender(1234,1000,1000,0x20001,"sys.boot_completed","true",owned)==-1);
 owned[0]=1;assert(as_ready_sender(1,1000,1000,0x20001,"servicemanager.ready","true",owned)==-1);
 assert(as_reap_owned(0,-1)==EINVAL);assert(as_reap_owned(-1,-1)==EINVAL);assert(as_reap_owned(1,-1)==EINVAL);
 /* Parent is not ours to signal, even when given its real pidfd. */
 int parentfd=(int)syscall(SYS_pidfd_open,getppid(),0);assert(parentfd>=0);
 assert(as_reap_owned(getppid(),parentfd)==ECHILD);close(parentfd);
 pid_t unrelated=child(),first=child(),second=child();
 int fd=(int)syscall(SYS_pidfd_open,first,0);assert(fd>=0);assert(!as_reap_owned(first,fd));close(fd);
 assert(!as_reap_owned(second,-1)); /* pidfd creation failure still reaps owned PID. */
 assert(as_reap_owned(second,-1)==ECHILD); /* no signalling after reaping */
 assert(!kill(unrelated,0));assert(!as_reap_owned(unrelated,-1));
 pid_t exited=fork();assert(exited>=0);if(!exited)_exit(7);
 assert(!as_reap_owned(exited,-1));
 return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    p=Path(temp);(p/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-I',str(ROOT/'runtime/pd2425/include'),str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True,timeout=10)
print('PASS: exact owned ready senders; no root/cross-service/foreign writes; pidfd and fallback cleanup, unowned/reaped PIDs rejected')
