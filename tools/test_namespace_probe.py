"""Fake namespace/mount/Binder syscalls; no mounts, network changes or Binder I/O on CI."""
import json,os,subprocess,tempfile
from pathlib import Path
from pd2425_build import generate_services
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);generate_services(d);(d/'sys').mkdir()
    (d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char *,char *);\n')
    source=r'''
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
static int ns_stat(const char*,struct stat*);
static int ns_unshare(int);
static int ns_mount(const char*,const char*,const char*,unsigned long,const void*);
static int ns_mkdir(const char*,mode_t);
static int ns_open(const char*,int,...);
static int ns_ioctl(int,unsigned long,...);
static int ns_close(int);
#define stat(path,info) ns_stat(path,info)
#define unshare(flags) ns_unshare(flags)
#define mount(a,b,c,d,e) ns_mount(a,b,c,d,e)
#define mkdir(a,b) ns_mkdir(a,b)
#define open(...) ns_open(__VA_ARGS__)
#define ioctl(...) ns_ioctl(__VA_ARGS__)
#define close(fd) ns_close(fd)
#define main probe_main
#include "preflight.c"
#undef main
#undef stat
#undef unshare
#undef mount
#undef mkdir
#undef open
#undef ioctl
#undef close
#include <assert.h>
#include <stdarg.h>
int __system_property_get(const char *key,char *value){(void)key;*value=0;return 0;}
static struct {int fail,index,unshared,private_set,tmp,binder_dir,binder_mounted,allocated,opened,closed,current_device;int fds[4];} fake;
static int failure(int point){if(fake.fail==point){errno=EACCES;return 1;}return 0;}
static int ns_unshare(int flags){assert(flags==(CLONE_NEWNS|CLONE_NEWNET));if(failure(1))return -1;fake.unshared=1;return 0;}
static int ns_mount(const char *source,const char *target,const char *type,unsigned long flags,const void *data){
 if(!strcmp(target,"/")){assert(fake.unshared&&!source&&!type&&!data&&flags==(MS_REC|MS_PRIVATE));if(failure(2))return -1;fake.private_set=1;return 0;}
 assert(fake.private_set&&strstr(target,"/data/local/tmp/test_ns/")==target);
 if(!strcmp(type,"tmpfs")){assert(!strcmp(source,"tmpfs")&&(flags&MS_NODEV)&&!strcmp(data,"size=1m,mode=0700"));if(failure(3))return -1;fake.tmp=1;return 0;}
 assert(!strcmp(type,"binder")&&!strcmp(source,"binder")&&fake.binder_dir&&flags==(MS_NOSUID|MS_NOEXEC)&&!strcmp(data,"max=4"));
 if(failure(5))return -1;
 fake.binder_mounted=1;return 0;
}
static int ns_mkdir(const char *path,mode_t mode){assert(fake.tmp&&strstr(path,"/data/local/tmp/test_ns/")==path&&strstr(path,"/binderfs")&&mode==0700);if(failure(4))return -1;fake.binder_dir=1;return 0;}
static int node_number(const char *path){const char *name=strrchr(path,'/');assert(name);name++;for(int n=0;n<3;n++)if(!strcmp(name,pd_binder_names[n]))return n;assert(0);return 0;}
static unsigned node_major(void){return fake.fail==12?10:600;}
static unsigned node_minor(int n){return fake.fail==12?0:100+fake.index*3+(unsigned)n;}
static int ns_stat(const char *path,struct stat *info){
 memset(info,0,sizeof(*info));
 if(!strcmp(path,"/proc/self/ns/mnt")){assert(fake.private_set);info->st_dev=5;info->st_ino=fake.fail==13?10:101+fake.index;return 0;}
 if(!strcmp(path,"/proc/self/ns/net")){assert(fake.private_set);info->st_dev=5;info->st_ino=fake.fail==14?20:201+fake.index;return 0;}
 assert(fake.binder_mounted&&strstr(path,"/data/local/tmp/test_ns/")==path);if(failure(8))return -1;
 int n=node_number(path);info->st_mode=S_IFCHR|0600;info->st_rdev=makedev(node_major(),node_minor(n));return 0;
}
static int ns_open(const char *path,int flags,...){
 if(!strcmp(path,"/proc/sys/kernel/random/boot_id")){errno=ENOENT;return -1;}
 assert(fake.binder_mounted&&strstr(path,"/data/local/tmp/test_ns/")==path); // Never /dev/binder.
 if(strstr(path,"binder-control")){assert(flags==(O_RDONLY|O_CLOEXEC|O_NOFOLLOW));if(failure(6))return -1;fake.opened++;fake.fds[0]=1;return 100;}
 assert(flags==(O_RDWR|O_CLOEXEC|O_NOFOLLOW));if(failure(9))return -1;
 int n=node_number(path);fake.current_device=n;fake.opened++;fake.fds[n+1]=1;return 200+n;
}
static int ns_ioctl(int fd,unsigned long request,...){
 va_list args;va_start(args,request);void *ptr=va_arg(args,void*);va_end(args);
 if(request==BINDER_CTL_ADD){assert(fd==100&&fake.fds[0]);if(failure(7))return -1;struct binderfs_device *dev=ptr;int n=fake.allocated;assert(n<3&&!strcmp(dev->name,pd_binder_names[n]));dev->major=node_major();dev->minor=node_minor(n);fake.allocated++;return 0;}
 assert(request==BINDER_VERSION&&fd==200+fake.current_device);if(failure(10))return -1;
 ((struct binder_version*)ptr)->protocol_version=fake.fail==11?7:BINDER_CURRENT_PROTOCOL_VERSION;return 0;
}
static int ns_close(int fd){int index=fd==100?0:fd-200+1;assert(index>=0&&index<=3&&fake.fds[index]);fake.fds[index]=0;fake.closed++;return 0;}
int main(int argc,char **argv){
 if(argc>1)return probe_main(argc,argv);
 struct pd_namespace_context ctx={0};ctx.parent_mnt.st_dev=ctx.parent_net.st_dev=5;ctx.parent_mnt.st_ino=10;ctx.parent_net.st_ino=20;
 strcpy(ctx.targets[0],"/data/local/tmp/test_ns/one");strcpy(ctx.targets[1],"/data/local/tmp/test_ns/two");
 for(int n=0;n<3;n++){ctx.host_present[n]=1;ctx.host_binders[n].st_rdev=makedev(10,n);}
 for(int point=0;point<=14;point++){
  memset(&fake,0,sizeof(fake));fake.fail=point;struct pd_namespace_child result;
  pd_namespace_worker(&ctx,0,&result);assert(fake.opened==fake.closed);
  if(!point)assert(!result.error&&result.devices_created==3&&!strcmp(result.stage,"complete")&&result.private_network&&result.private_mounts);
  else assert(result.error);
  if(point==1||point==2||point==13||point==14)assert(!fake.tmp&&!fake.binder_mounted&&!fake.opened);
 }
 for(int n=0;n<2;n++){memset(&fake,0,sizeof(fake));fake.index=n;pd_namespace_worker(&ctx,n,&ctx.children[n]);ctx.received[n]=1;}
 assert(pd_namespace_results_valid(&ctx)==0);
 struct pd_namespace_context bad=ctx;bad.children[1].minors[0]=bad.children[0].minors[1];assert(pd_namespace_results_valid(&bad)==EADDRINUSE);
 bad=ctx;bad.children[1].mnt_ino=bad.children[0].mnt_ino;assert(pd_namespace_results_valid(&bad)==EXDEV);
 bad=ctx;bad.children[1].majors[0]=10;bad.children[1].minors[0]=0;assert(pd_namespace_results_valid(&bad)==EXDEV);
 bad=ctx;bad.children[1].protocol[2]=7;assert(pd_namespace_results_valid(&bad)==EPROTO);
 bad=ctx;bad.received[1]=0;assert(pd_namespace_results_valid(&bad)==ENODATA);
 return 0;
}
'''
    (d/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-Wall','-Wextra','-Werror','-I',str(d),'-I',str(ROOT/'runtime/pd2425/include'),'-I',str(ROOT/'runtime/pd2425/src'),str(d/'test.c'),'-o',str(d/'test')],check=True)
    subprocess.run([str(d/'test')],check=True,timeout=10)
    refused=subprocess.run([str(d/'test'),'--test-isolation'],capture_output=True,text=True,timeout=5)
    assert refused.returncode==31
    report=json.loads(refused.stdout)
    assert report['component']=='namespace-self-test' and report['runtime_ready'] is False
    assert report['passed'] is False and report['spawned']==0 and report['group_created'] is False
print('PASS: namespace ordering, private-only Binder opens, protocol/alias rejection, fail-closed stages and FD cleanup (mock kernel)')
