"""Service BPF and Binder reply parser; no mounts or real Binder transactions."""
import os,subprocess,tempfile
from pathlib import Path
from pd2425_build import generate_services
ROOT=Path(__file__).resolve().parents[1]
source=r'''
#define main preview_main
#include "gsi_preview.c"
#undef main
#include <assert.h>
#include <pthread.h>
int __system_property_get(const char *name,char *value){(void)name;*value=0;return 0;}
static uint32_t evaluate(struct sock_filter *filter,size_t count,unsigned arch,unsigned nr,uint64_t *args){
 uint32_t a=0;for(size_t pc=0;pc<count;pc++){
  struct sock_filter i=filter[pc];
  if(i.code==(BPF_LD|BPF_W|BPF_ABS)){if(i.k==offsetof(struct seccomp_data,arch))a=arch;else if(i.k==offsetof(struct seccomp_data,nr))a=nr;else{unsigned off=i.k-(unsigned)offsetof(struct seccomp_data,args);assert(off<48&&off%4==0);a=(uint32_t)(args[off/8]>>((off%8)*8));}}
  else if(i.code==(BPF_JMP|BPF_JEQ|BPF_K))pc+=a==i.k?i.jt:i.jf;
  else if(i.code==(BPF_JMP|BPF_JSET|BPF_K))pc+=(a&i.k)?i.jt:i.jf;
  else {assert(i.code==(BPF_RET|BPF_K));return i.k;}
 }assert(0);return 0;
}
static void *thread_probe(void *arg){
 pid_t tgid=*(pid_t*)arg;assert(getpid()==tgid&&syscall(SYS_gettid)!=tgid);assert(!pv_test_filter());return (void*)123;
}
struct held_thread {int ready,hold;pid_t tgid;};
static void *thread_hold(void *arg){struct held_thread *state=arg;assert(getpid()==state->tgid&&syscall(SYS_gettid)!=state->tgid&&!pv_test_filter());assert(write(state->ready,"T",1)==1);char value;ssize_t ignored=read(state->hold,&value,1);(void)ignored;return NULL;}
int main(void){
 struct sock_filter filter[512];assert(!sm_build_policy(filter,1)&&errno==E2BIG);size_t count=sm_build_policy(filter,512);assert(count>0);
 uint64_t args[6]={0};uint32_t deny=SECCOMP_RET_ERRNO|EPERM;
 assert(evaluate(filter,count,PD_GUARD_ARCH^1,SYS_write,args)==SECCOMP_RET_KILL_PROCESS);
 unsigned calls[]={SYS_clone,SYS_fork,SYS_vfork,SYS_socket,SYS_socketpair,SYS_kill,SYS_tgkill,SYS_ptrace,SYS_process_vm_writev,SYS_pidfd_getfd,SYS_bpf,SYS_perf_event_open,SYS_mount,SYS_umount2,SYS_setns,SYS_unshare,SYS_capset,SYS_setresuid,SYS_reboot,SYS_seccomp,SYS_open_by_handle_at};
 for(unsigned n=0;n<sizeof(calls)/sizeof(calls[0]);n++)assert(evaluate(filter,count,PD_GUARD_ARCH,calls[n],args)==deny);
 args[0]=SM_THREAD_FLAGS;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_clone,args)==SECCOMP_RET_ALLOW);
 for(unsigned bit=0;bit<64;bit++){args[0]=(uint64_t)SM_THREAD_FLAGS^(1ULL<<bit);assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_clone,args)==deny);}
#ifdef SYS_clone3
 assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_clone3,args)==(SECCOMP_RET_ERRNO|ENOSYS));
#endif
 memset(args,0,sizeof(args));
 unsigned ioctls[]={BINDER_VERSION,BINDER_WRITE_READ,BINDER_SET_CONTEXT_MGR,BINDER_SET_CONTEXT_MGR_EXT,BINDER_SET_MAX_THREADS,BINDER_THREAD_EXIT};
 for(unsigned n=0;n<sizeof(ioctls)/sizeof(ioctls[0]);n++){args[1]=ioctls[n];assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_ioctl,args)==SECCOMP_RET_ALLOW);}
 args[1]=BINDER_CTL_ADD;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_ioctl,args)==deny);
#ifdef BINDER_FREEZE
 args[1]=BINDER_FREEZE;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_ioctl,args)==deny);
#endif
 args[1]=0x5401;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_ioctl,args)==deny);
 memset(args,0,sizeof(args));args[2]=O_RDWR;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_openat,args)==SECCOMP_RET_ALLOW);
 int flags[]={O_WRONLY,O_RDWR|O_CREAT,O_RDWR|O_TRUNC,O_RDWR|O_APPEND,O_RDWR|O_TMPFILE};
 for(unsigned n=0;n<sizeof(flags)/sizeof(flags[0]);n++){args[2]=(uint64_t)flags[n];assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_openat,args)==deny);}
 memset(args,0,sizeof(args));args[1]=F_SETFL;args[2]=O_RDWR|O_NONBLOCK;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_fcntl,args)==SECCOMP_RET_ALLOW);args[2]|=O_ASYNC;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_fcntl,args)==deny);
 args[1]=F_SETOWN;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_fcntl,args)==deny);
 memset(args,0,sizeof(args));args[0]=PR_GET_NO_NEW_PRIVS;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_prctl,args)==SECCOMP_RET_ALLOW);args[0]=PR_SET_NAME;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_prctl,args)==deny);
 memset(args,0,sizeof(args));args[0]=PR_SET_PDEATHSIG;args[1]=SIGKILL;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_prctl,args)==SECCOMP_RET_ALLOW);
 args[1]=0;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_prctl,args)==deny);args[1]=SIGTERM;assert(evaluate(filter,count,PD_GUARD_ARCH,SYS_prctl,args)==deny);
 unsigned char reply[4+sizeof(struct binder_transaction_data)]={0};uint32_t command=BR_REPLY;struct binder_transaction_data data={0};memcpy(reply,&command,4);memcpy(reply+4,&data,sizeof(data));
 unsigned char mapping[32]={0};assert(sm_parse_ping(reply,sizeof(reply),mapping,sizeof(mapping))==1);
 assert(sm_parse_ping(reply,sizeof(reply)-1,mapping,sizeof(mapping))==-EPROTO);
 data.flags=TF_STATUS_CODE;data.data_size=4;data.data.ptr.buffer=(binder_uintptr_t)(uintptr_t)mapping;memcpy(reply+4,&data,sizeof(data));assert(sm_parse_ping(reply,sizeof(reply),mapping,sizeof(mapping))==1);
 data.data.ptr.buffer=(binder_uintptr_t)(uintptr_t)(mapping+sizeof(mapping)-1);memcpy(reply+4,&data,sizeof(data));assert(sm_parse_ping(reply,sizeof(reply),mapping,sizeof(mapping))==-EPROTO);
 command=BR_DEAD_REPLY;memcpy(reply,&command,4);assert(sm_parse_ping(reply,4,mapping,sizeof(mapping))==-EAGAIN);
 pid_t child=fork();assert(child>=0);if(!child){
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||sm_install_policy()||pv_test_filter())_exit(50);
  errno=0;if(syscall(SYS_ioctl,-1L,BINDER_VERSION,NULL)!=-1||errno!=EBADF)_exit(51);
  errno=0;if(syscall(SYS_ioctl,-1L,BINDER_CTL_ADD,NULL)!=-1||errno!=EPERM)_exit(52);
  if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0))_exit(55);
  if(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2)_exit(53);
  int fd=(int)syscall(SYS_eventfd2,0,O_CLOEXEC|O_NONBLOCK);if(fd<0)_exit(54);close(fd);
  pid_t tgid=getpid();pthread_t thread;void *value=NULL;if(pthread_create(&thread,NULL,thread_probe,&tgid)||pthread_join(thread,&value)||value!=(void*)123)_exit(56);
  errno=0;if(syscall(SYS_clone,(unsigned long)SIGCHLD,NULL,NULL,NULL,NULL)!=-1||errno!=EPERM)_exit(57);
  _exit(0);
 }
 int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);assert(kill(getpid(),0)==0);
 int ready[2],hold[2];assert(!pipe(ready)&&!pipe(hold));child=fork();assert(child>=0);
 if(!child){close(ready[0]);close(hold[1]);if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||sm_install_policy())_exit(60);
  struct held_thread state={ready[1],hold[0],getpid()};pthread_t thread;if(pthread_create(&thread,NULL,thread_hold,&state))_exit(61);char value;ssize_t ignored=read(hold[0],&value,1);(void)ignored;_exit(62);
 }
 close(ready[1]);close(hold[0]);int pidfd=(int)syscall(SYS_pidfd_open,child,0);assert(pidfd>=0);
 struct pollfd waiting={ready[0],POLLIN,0};assert(poll(&waiting,1,2000)==1&&(waiting.revents&POLLIN));char marker;assert(read(ready[0],&marker,1)==1&&marker=='T');
 assert(!syscall(SYS_pidfd_send_signal,pidfd,SIGKILL,NULL,0));assert(pd_wait_pidfd(pidfd,2000)==0);assert(waitpid(child,&status,0)==child&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
 close(pidfd);close(ready[0]);close(hold[1]);return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);generate_services(d);(d/'sys').mkdir();(d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char*,char*);\n')
    (d/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-O2','-pthread','-Wall','-Wextra','-Werror','-I',str(d),'-I',str(ROOT/'runtime/pd2425/include'),'-I',str(ROOT/'runtime/pd2425/src'),str(d/'test.c'),'-o',str(d/'test')],check=True)
    subprocess.run([str(d/'test')],check=True,timeout=10,env={**os.environ,'GLIBC_TUNABLES':'glibc.pthread.rseq=0'})
print('PASS: strict service syscall/Binder ioctl policy, no file creation/fork/signals, real pthread create/join and pidfd termination of whole owned thread group; bounded Binder reply parsing')
