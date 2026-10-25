"""Real owned child processes/pidfds, simulated cgroup FS. No host cgroup writes."""
import os,subprocess,tempfile
from pathlib import Path
from pd2425_build import generate_services
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);generate_services(d);(d/'sys').mkdir()
    (d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char *,char *);\n')
    source=r'''
#define main probe_main
#include "preflight.c"
#undef main
#include <assert.h>
#include <sys/mman.h>
int __system_property_get(const char *key,char *value){(void)key;*value=0;return 0;}
struct fake {pid_t children[2];int count,created,removed,kills,fail,checked,report[2];volatile int *started;};
static int create(void *ctx){struct fake *f=ctx;if(f->fail==1)return EACCES;f->created=1;return 0;}
static int add(void *ctx,pid_t child){
 struct fake *f=ctx;assert(child>1&&child!=getpid());assert(f->count<2);
 f->children[f->count++]=child;return f->fail==2?EPERM:0;
}
static int members(void *ctx,const pid_t *children){
 struct fake *f=ctx;assert(f->count==2&&children[0]==f->children[0]&&children[1]==f->children[1]);
 if(f->started)assert(*f->started==0);
 f->checked=1;
 return f->fail==3?EBUSY:0;
}
static int populated(void *ctx){struct fake *f=ctx;return f->count&&!f->kills?1:0;}
static int group_kill(void *ctx){
 struct fake *f=ctx;assert(f->count==2);if(f->fail==4)return EACCES;
 if(f->started)assert(f->checked&&*f->started==3);
 f->kills++;for(int i=0;i<2;i++)assert(kill(f->children[i],SIGKILL)==0);return 0;
}
static int remove_group(void *ctx){struct fake *f=ctx;f->removed=1;if(f->started)for(int n=0;n<2;n++)if(f->report[n]>=0)close(f->report[n]);return f->fail==5?EBUSY:0;}
static void child_work(void *ctx,int index){
 struct fake *f=ctx;close(f->report[0]);__sync_fetch_and_or(f->started,1<<index);
 assert(write(f->report[1],&index,sizeof(index))==(ssize_t)sizeof(index));close(f->report[1]);
}
static int inspect(void *ctx,const pid_t *children){
 struct fake *f=ctx;assert(f->checked&&children[0]==f->children[0]&&children[1]==f->children[1]);close(f->report[1]);f->report[1]=-1;int seen=0;
 for(int n=0;n<2;n++){
  struct pollfd ready={.fd=f->report[0],.events=POLLIN};assert(poll(&ready,1,1000)>0);
  int index;assert(read(f->report[0],&index,sizeof(index))==(ssize_t)sizeof(index));assert(index>=0&&index<=1&&!(seen&(1<<index)));seen|=1<<index;
 }
 assert(seen==3&&*f->started==3);return f->fail==6?EPERM:0;
}
int main(void){
 pid_t sentinel_owner=getpid();pid_t sentinel=fork();assert(sentinel>=0);
 if(!sentinel){assert(prctl(PR_SET_PDEATHSIG,SIGKILL)==0);if(getppid()!=sentinel_owner)_exit(1);for(;;)pause();}
 for(int failure=0;failure<=5;failure++){
  struct fake f={.fail=failure};struct pd_cgroup_ops ops={.create=create,.add=add,.members=members,.populated=populated,.kill_group=group_kill,.remove_group=remove_group,.context=&f};struct pd_cgroup_result result;
  int rc=pd_cgroup_run(&ops,&result);assert(f.removed&&result.spawned==result.reaped);
  for(int i=0;i<f.count;i++){int status;errno=0;assert(waitpid(f.children[i],&status,WNOHANG)==-1&&errno==ECHILD);}
  assert(kill(sentinel,0)==0); // Unrelated live child must survive all paths.
  if(!failure)assert(rc==0&&result.pidfds==2&&result.membership_verified&&result.kill_succeeded&&result.drained&&result.reaped==2);
  else assert(rc==40);
  if(failure<=3&&failure)assert(f.kills==0);
  if(failure==5)assert(result.cleanup_errno==EBUSY);
 }
 for(int mode=0;mode<3;mode++){
  volatile int *started=mmap(NULL,sizeof(int),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);assert(started!=MAP_FAILED);*started=0;
  struct fake f={.fail=mode==1?6:mode==2?3:0,.started=started,.report={-1,-1}};assert(pipe2(f.report,O_CLOEXEC)==0);
  struct pd_cgroup_ops ops={.create=create,.add=add,.members=members,.populated=populated,.kill_group=group_kill,.remove_group=remove_group,.context=&f,.child_task=child_work,.inspect_children=inspect};struct pd_cgroup_result result;
  struct sigaction before,after_pipe;assert(sigaction(SIGPIPE,NULL,&before)==0);
  int rc=pd_cgroup_run(&ops,&result);assert(sigaction(SIGPIPE,NULL,&after_pipe)==0&&before.sa_handler==after_pipe.sa_handler);
  assert(f.removed&&result.spawned==result.reaped&&kill(sentinel,0)==0);
  if(!mode)assert(rc==0&&f.kills==1&&*started==3);
  else assert(rc==40&&f.kills==0);
  if(mode==2)assert(*started==0); // No work before exact membership verification.
  assert(munmap((void*)started,sizeof(int))==0);
 }
 struct sigaction ignored={0},old,after;ignored.sa_handler=SIG_IGN;sigemptyset(&ignored.sa_mask);assert(sigaction(SIGCHLD,&ignored,&old)==0);
 struct fake f={0};struct pd_cgroup_ops ops={.create=create,.add=add,.members=members,.populated=populated,.kill_group=group_kill,.remove_group=remove_group,.context=&f};struct pd_cgroup_result result;
 assert(pd_cgroup_run(&ops,&result)==0&&result.reaped==2);assert(sigaction(SIGCHLD,NULL,&after)==0&&after.sa_handler==SIG_IGN);
 assert(sigaction(SIGCHLD,&old,NULL)==0);
 assert(kill(sentinel,SIGKILL)==0);assert(waitpid(sentinel,NULL,0)==sentinel);
 return 0;
}
'''
    (d/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-Wall','-Wextra','-Werror','-I',str(d),'-I',str(ROOT/'runtime/pd2425/include'),'-I',str(ROOT/'runtime/pd2425/src'),str(d/'test.c'),'-o',str(d/'test')],check=True)
    subprocess.run([str(d/'test')],check=True,timeout=20)
print('PASS: child-only termination, denied operations, foreign-member rejection, cleanup; unrelated process survives')
