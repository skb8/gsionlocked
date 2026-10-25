"""Mocked PID/proc/rootfs syscalls: no clone, chroot, mounts or fd closure on CI."""
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
#include <sys/vfs.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sched.h>
#include <dirent.h>
static int bs_stat(const char*,struct stat*);
static int bs_lstat(const char*,struct stat*);
static int bs_statfs(const char*,struct statfs*);
static int bs_unshare(int);
static int bs_mount(const char*,const char*,const char*,unsigned long,const void*);
static int bs_mkdir(const char*,mode_t);
static int bs_chroot(const char*);
static int bs_chdir(const char*);
static pid_t bs_getpid(void),bs_getppid(void);
static ssize_t bs_readlink(const char*,char*,size_t);
static DIR *bs_opendir(const char*);
static struct dirent *bs_readdir(DIR*);
static int bs_closedir(DIR*);
static long bs_syscall(long,...);
#define stat(a,b) bs_stat(a,b)
#define lstat(a,b) bs_lstat(a,b)
#define statfs(a,b) bs_statfs(a,b)
#define unshare(a) bs_unshare(a)
#define mount(a,b,c,d,e) bs_mount(a,b,c,d,e)
#define mkdir(a,b) bs_mkdir(a,b)
#define chroot(a) bs_chroot(a)
#define chdir(a) bs_chdir(a)
#define getpid() bs_getpid()
#define getppid() bs_getppid()
#define readlink(a,b,c) bs_readlink(a,b,c)
#define opendir(a) bs_opendir(a)
#define readdir(a) bs_readdir(a)
#define closedir(a) bs_closedir(a)
#define syscall(...) bs_syscall(__VA_ARGS__)
#define main probe_main
#include "preflight.c"
#undef main
#include <assert.h>
#include <stdarg.h>
int __system_property_get(const char *k,char *v){(void)k;*v=0;return 0;}
static struct {const char *fail;int index,shared_pid,create_mode,unshared,private_set,tmp,proc,readonly,closed,root,cwd,entry;} fake;
static int fault(const char *name){if(fake.fail&&!strcmp(fake.fail,name)){errno=EACCES;return 1;}return 0;}
static pid_t bs_getpid(void){return fake.shared_pid?400+fake.index:fake.fail&&!strcmp(fake.fail,"bad_pid")?4:1;}
static pid_t bs_getppid(void){return fake.shared_pid?200:fake.fail&&!strcmp(fake.fail,"bad_parent")?1:0;}
static int bs_unshare(int flags){assert(flags==CLONE_NEWNS);if(fault("unshare"))return -1;fake.unshared=1;return 0;}
static int bs_mount(const char *src,const char *path,const char *type,unsigned long flags,const void *data){
 if(!strcmp(path,"/")){assert(fake.unshared&&!src&&!type&&!data&&flags==(MS_REC|MS_PRIVATE));if(fault("private"))return -1;fake.private_set=1;return 0;}
 assert(fake.private_set&&strstr(path,"/data/local/tmp/test_boot/")==path);
 if(flags&MS_REMOUNT){assert(fake.tmp&&(fake.proc||fake.shared_pid)&&!src&&!type&&!data&&(flags&MS_RDONLY));if(fault("readonly"))return -1;fake.readonly=1;return 0;}
 if(!strcmp(type,"tmpfs")){assert(!strcmp(src,"tmpfs")&&!strcmp(data,"size=1m,mode=0700")&&(flags&MS_NODEV));if(fault("tmpfs"))return -1;fake.tmp=1;return 0;}
 assert(!strcmp(type,"proc")&&!strcmp(src,"proc")&&!data&&fake.tmp&&(flags&MS_RDONLY)&&(flags&MS_NODEV));if(fault("proc_mount"))return -1;fake.proc=1;return 0;
}
static int bs_mkdir(const char *path,mode_t mode){assert(fake.tmp&&strstr(path,"/proc")&&mode==0700);return fault("mkdir")?-1:0;}
static int bs_stat(const char *path,struct stat *info){
 memset(info,0,sizeof(*info));
 if(!strcmp(path,"/proc/self/ns/pid")){assert(!fake.shared_pid);if(fake.create_mode){errno=ENOENT;return -1;}assert(fake.private_set);if(fault("pid_stat"))return -1;info->st_dev=5;info->st_ino=fault("same_pid")?10:50+fake.index;return 0;}
 if(!strcmp(path,"/proc/self/ns/mnt")){assert(fake.private_set);if(fault("mnt_stat"))return -1;info->st_dev=5;info->st_ino=fault("same_mnt")?20:100+fake.index;return 0;}
 assert(!strcmp(path,"/")&&(fake.cwd||fake.create_mode));if(fault("root_stat"))return -1;info->st_dev=fault("same_root")?10:500+fake.index;info->st_ino=1;info->st_mode=S_IFDIR|0700;return 0;
}
static int bs_lstat(const char *path,struct stat *info){(void)info;assert(fake.cwd&&(strcmp(path,"/proc")||fake.shared_pid));if(!strcmp(path,"/proc")&&fault("proc_present"))return 0;if(fault("host_path_present"))return 0;errno=ENOENT;return -1;}
static int bs_statfs(const char *path,struct statfs *info){
 assert(fake.cwd&&fake.readonly);memset(info,0,sizeof(*info));info->f_flags=ST_RDONLY;
 if(!strcmp(path,"/")){if(fault("rootfs_type"))return -1;info->f_type=fault("bad_rootfs_type")?0:TMPFS_MAGIC;if(fault("root_writable"))info->f_flags=0;}
 else {assert(!strcmp(path,"/proc")&&fake.proc);if(fault("proc_type"))return -1;info->f_type=fault("bad_proc_type")?0:PROC_SUPER_MAGIC;if(fault("proc_writable"))info->f_flags=0;}
 return 0;
}
static long bs_syscall(long request,...){
 assert(request==SYS_close_range&&fake.readonly);va_list args;va_start(args,request);unsigned first=va_arg(args,unsigned),last=va_arg(args,unsigned),flags=va_arg(args,unsigned);va_end(args);
 assert(!flags);if(!fake.closed)assert(first==0&&last==6);else assert(first==8&&last==UINT_MAX);
 if(fault("close_range"))return -1;
 fake.closed++;return 0;
}
static int bs_chroot(const char *path){assert(fake.closed==2&&fake.readonly&&strstr(path,"/data/local/tmp/test_boot/")==path);if(fault("chroot"))return -1;fake.root=1;return 0;}
static int bs_chdir(const char *path){assert(fake.root&&!strcmp(path,"/"));if(fault("chdir"))return -1;fake.cwd=1;return 0;}
static ssize_t bs_readlink(const char *path,char *out,size_t size){assert(fake.cwd&&size>1&&!strcmp(path,"/proc/self"));if(fault("readlink"))return -1;out[0]=fault("bad_proc_self")?'2':'1';return 1;}
static DIR *bs_opendir(const char *path){assert(fake.cwd&&!strcmp(path,"/proc"));if(fault("opendir"))return NULL;return (DIR*)&fake;}
static struct dirent *bs_readdir(DIR *dir){assert(dir==(DIR*)&fake);static struct dirent entry;memset(&entry,0,sizeof(entry));const char *names[]={".","..","self","1"};
 if(fake.entry<4){strcpy(entry.d_name,names[fake.entry++]);return &entry;}
 if(fake.entry++==4&&fault("host_pid_visible")){strcpy(entry.d_name,"22");return &entry;}
 if(fault("readdir"))return NULL;
 errno=0;return NULL;
}
static int bs_closedir(DIR *dir){assert(dir==(DIR*)&fake);return 0;}
int main(int argc,char **argv){
 if(argc>1)return probe_main(argc,argv);
 struct pd_boot_context ctx={0};ctx.parent_pid.st_dev=ctx.ns.parent_mnt.st_dev=5;ctx.parent_pid.st_ino=10;ctx.ns.parent_mnt.st_ino=20;ctx.parent_root.st_dev=10;ctx.parent_root.st_ino=1;ctx.ns.report_fd[1]=7;
 strcpy(ctx.ns.targets[0],"/data/local/tmp/test_boot/one");strcpy(ctx.ns.targets[1],"/data/local/tmp/test_boot/two");
 const char *failures[]={NULL,"bad_pid","bad_parent","unshare","private","pid_stat","mnt_stat","same_pid","same_mnt","tmpfs","mkdir","proc_mount","readonly","close_range","chroot","chdir","root_stat","same_root","rootfs_type","bad_rootfs_type","root_writable","proc_type","bad_proc_type","proc_writable","readlink","bad_proc_self","opendir","host_pid_visible","readdir","host_path_present"};
 for(unsigned n=0;n<sizeof(failures)/sizeof(failures[0]);n++){
  memset(&fake,0,sizeof(fake));fake.fail=failures[n];struct pd_boot_child r;pd_boot_worker(&ctx,0,&r);
  if(!n)assert(!r.error&&!strcmp(r.stage,"complete")&&r.fds_closed&&r.root_read_only&&r.proc_read_only);
  else assert(r.error);
  if(n<=8&&n)assert(!fake.tmp&&!fake.closed&&!fake.root);
 }
 for(int n=0;n<2;n++){memset(&fake,0,sizeof(fake));fake.index=n;pd_boot_worker(&ctx,n,&ctx.children[n]);ctx.received[n]=1;}
 assert(pd_boot_results_valid(&ctx)==0);
 struct pd_boot_context bad=ctx;bad.children[1].pid_ino=ctx.children[0].pid_ino;assert(pd_boot_results_valid(&bad)==EXDEV);
 bad=ctx;bad.children[1].root_dev=ctx.children[0].root_dev;assert(pd_boot_results_valid(&bad)==EXDEV);
 bad=ctx;bad.children[1].fds_closed=0;assert(pd_boot_results_valid(&bad)==EPROTO);
 bad=ctx;bad.children[1].proc_pid_count=2;assert(pd_boot_results_valid(&bad)==EPROTO);
 ctx.rootfs_only=1;
 for(int n=0;n<2;n++){
  memset(&fake,0,sizeof(fake));fake.index=n;fake.shared_pid=1;pd_boot_worker(&ctx,n,&ctx.children[n]);ctx.received[n]=1;
  assert(!ctx.children[n].error&&ctx.children[n].pid>1&&!ctx.children[n].pid_ino&&!fake.proc&&!fake.entry&&fake.closed==2);
 }
 assert(pd_boot_results_valid(&ctx)==0);
 const char *rf_failures[]={"root_writable","chroot","close_range","proc_present","host_path_present"};
 for(unsigned n=0;n<sizeof(rf_failures)/sizeof(rf_failures[0]);n++){
  memset(&fake,0,sizeof(fake));fake.shared_pid=1;fake.fail=rf_failures[n];struct pd_boot_child r;pd_boot_worker(&ctx,0,&r);assert(r.error&&!fake.proc);
 }
 bad=ctx;bad.children[0].proc_read_only=1;assert(pd_boot_results_valid(&bad)==EPROTO);
 bad=ctx;bad.children[0].pid=1;assert(pd_boot_results_valid(&bad)==EPROTO);
 bad=ctx;bad.children[0].pid_ino=100;assert(pd_boot_results_valid(&bad)==EPROTO);
 memset(&fake,0,sizeof(fake));fake.create_mode=1;ctx.rootfs_only=0;
 assert(pd_boot_create(&ctx)==ENOENT&&!strcmp(ctx.setup_stage,"parent_pid_namespace")&&!fake.tmp);
 memset(&fake,0,sizeof(fake));fake.create_mode=1;fake.shared_pid=1;fake.fail="root_stat";ctx.rootfs_only=1;
 assert(pd_boot_create(&ctx)==EACCES&&!strcmp(ctx.setup_stage,"parent_root"));
 return 0;
}
'''
    (d/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-Wall','-Wextra','-Werror','-I',str(d),'-I',str(ROOT/'runtime/pd2425/include'),'-I',str(ROOT/'runtime/pd2425/src'),str(d/'test.c'),'-o',str(d/'test')],check=True)
    subprocess.run([str(d/'test')],check=True,timeout=10)
    r=subprocess.run([str(d/'test'),'--test-bootstrap'],capture_output=True,text=True,timeout=5)
    assert r.returncode==31
    report=json.loads(r.stdout)
    assert report['component']=='bootstrap-self-test' and report['spawned']==0 and report['runtime_ready'] is False
    r=subprocess.run([str(d/'test'),'--test-rootfs'],capture_output=True,text=True,timeout=5)
    report=json.loads(r.stdout)
    assert r.returncode==31 and report['component']=='rootfs-self-test'
    assert report['pid_namespace_required'] is False and report['proc_required'] is False and report['spawned']==0
print('PASS: PID1/private proc/read-only rootfs, FD closure ordering, host-path/PID rejection and partial failures (mock kernel)')
