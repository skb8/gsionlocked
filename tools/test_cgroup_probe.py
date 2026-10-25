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
int __system_property_get(const char *key,char *value){(void)key;*value=0;return 0;}
struct fake {pid_t children[2];int count,created,removed,kills,fail;};
static int create(void *ctx){struct fake *f=ctx;if(f->fail==1)return EACCES;f->created=1;return 0;}
static int add(void *ctx,pid_t child){
 struct fake *f=ctx;assert(child>1&&child!=getpid());assert(f->count<2);
 f->children[f->count++]=child;return f->fail==2?EPERM:0;
}
static int members(void *ctx,const pid_t *children){
 struct fake *f=ctx;assert(f->count==2&&children[0]==f->children[0]&&children[1]==f->children[1]);
 return f->fail==3?EBUSY:0;
}
static int populated(void *ctx){struct fake *f=ctx;return f->count&&!f->kills?1:0;}
static int group_kill(void *ctx){
 struct fake *f=ctx;assert(f->count==2);if(f->fail==4)return EACCES;
 f->kills++;for(int i=0;i<2;i++)assert(kill(f->children[i],SIGKILL)==0);return 0;
}
static int remove_group(void *ctx){struct fake *f=ctx;f->removed=1;return f->fail==5?EBUSY:0;}
int main(void){
 pid_t sentinel_owner=getpid();pid_t sentinel=fork();assert(sentinel>=0);
 if(!sentinel){assert(prctl(PR_SET_PDEATHSIG,SIGKILL)==0);if(getppid()!=sentinel_owner)_exit(1);for(;;)pause();}
 for(int failure=0;failure<=5;failure++){
  struct fake f={.fail=failure};struct pd_cgroup_ops ops={create,add,members,populated,group_kill,remove_group,&f};struct pd_cgroup_result result;
  int rc=pd_cgroup_run(&ops,&result);assert(f.removed&&result.spawned==result.reaped);
  for(int i=0;i<f.count;i++){int status;errno=0;assert(waitpid(f.children[i],&status,WNOHANG)==-1&&errno==ECHILD);}
  assert(kill(sentinel,0)==0); // Unrelated live child must survive all paths.
  if(!failure)assert(rc==0&&result.pidfds==2&&result.membership_verified&&result.kill_succeeded&&result.drained&&result.reaped==2);
  else assert(rc==40);
  if(failure<=3&&failure)assert(f.kills==0);
  if(failure==5)assert(result.cleanup_errno==EBUSY);
 }
 struct sigaction ignored={0},old,after;ignored.sa_handler=SIG_IGN;sigemptyset(&ignored.sa_mask);assert(sigaction(SIGCHLD,&ignored,&old)==0);
 struct fake f={0};struct pd_cgroup_ops ops={create,add,members,populated,group_kill,remove_group,&f};struct pd_cgroup_result result;
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
