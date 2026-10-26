/* Reboot-recovery roadmap: bounded capless upstream GSI linker/shell preview.
   No HAL, Android framework, host service control, writable GSI or partitions. */
#pragma push_macro("main")
#undef main
#define main pd_diagnostic_main
#include "preflight.c"
#undef main
#pragma pop_macro("main")
#include <linux/loop.h>
#include <linux/openat2.h>
#include <linux/capability.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <grp.h>
#include "preview_image.h"
#include "preview_policy.h"
#include "preview_linkerconfig.h"
#include "service_kind.h"
#include "service_fs.h"
#include "service_exec_diag.h"
#include "service_client.h"
#include "service_policy.h"
#ifndef PD_SM_CHECK_SHA
#define PD_SM_CHECK_SHA ""
#define PD_SM_CHECK_BYTES 0
#endif
static int pv_helper_fd=-1;
static int pv_service_mode;
static const struct sm_kind *pv_kind(void){return pv_service_mode==3?&hw_service_kind:&sm_service_kind;}
static const char *pv_config(void){return pv_service_mode==3?pv_hw_config:pv_service_mode>=2?pv_smoke_config:pv_bootstrap_config;}
static size_t pv_config_bytes(void){return pv_service_mode==3?sizeof(pv_hw_config)-1:pv_service_mode>=2?sizeof(pv_smoke_config)-1:sizeof(pv_bootstrap_config)-1;}
struct pv_record {struct sm_exec_observation exec;struct sm_environment sm;int linkerconfig_readonly,prepared,error,stage,uid,gid,caps_zero,nnp,filter_verified,namespaces_private,loop_count,loops[2],loop_control_errno,loop_node_errno,loop_candidates,loop_preferred,loop_probe_number,loop_operation,loop_actual_major,loop_actual_minor,loop_expected_major,loop_expected_minor;};
struct pv_result {int thread_peak;int ping_passed,identity_verified,owned_stop,host_enforcing, ping_errno;int error,cleanup_error,spawned,reaped,exit_code,signal,metadata_received,parent_unchanged,loops_released,temp_removed;const char *stage;char digest[65],output[8193];struct pv_record child;};
static const char *pv_stages[]={"none","parent_death","private_namespaces","image_loop","image_mount","runtime_apex","runtime_loop","runtime_mount","elf_validation","chroot","drop_privileges","close_fds","seccomp","exec","bootstrap_linkerconfig","service_filesystems","service_domain"};
_Static_assert(sizeof(struct pv_record)<=PIPE_BUF,"atomic service setup record");
static int pv_inside(int root,const char *path,int flags){struct open_how how={.flags=(uint64_t)(flags|O_CLOEXEC),.resolve=RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS};return (int)syscall(SYS_openat2,root,path,&how,sizeof(how));}
/* GET_FREE may return a kernel loop whose /dev node ueventd has not created.
   Android may also omit loop-control entirely. Existing block nodes are safe
   candidates only after exact device validation and atomic LOOP_CONFIGURE. */
enum {PV_LOOP_CONTROL_OPEN=1,PV_LOOP_CONTROL_IDENTITY,PV_LOOP_GET_FREE,PV_LOOP_SYSFS_OPEN,PV_LOOP_SYSFS_READ,PV_LOOP_NODE_OPEN,PV_LOOP_NODE_STAT,PV_LOOP_NODE_IDENTITY,PV_LOOP_CONFIGURE};
static const char *pv_loop_operations[]={"none","control_open","control_identity","get_free","sysfs_open","sysfs_read","node_open","node_stat","node_identity","configure"};
/* Kernel loop minors may be shifted when max_part is set. Identify the main
   virtual loop from its kernel-owned sysfs dev attribute, never from a guessed
   minor or an arbitrary block-device path supplied by the image. */
static int pv_loop_parse(const char *value,dev_t *device){
    if(value[0]<'0'||value[0]>'9')return EPROTO;
    char *end=NULL;errno=0;unsigned long major_id=strtoul(value,&end,10);
    if(errno||major_id!=7||*end!=':')return EPROTO;
    const char *minor_text=end+1;if(*minor_text<'0'||*minor_text>'9')return EPROTO;
    errno=0;unsigned long minor_id=strtoul(minor_text,&end,10);
    if(errno||minor_id>1048575UL||(*end&&strcmp(end,"\n")))return EPROTO;
    *device=makedev((unsigned)major_id,(unsigned)minor_id);return 0;
}
static int pv_loop_device(int n,dev_t *device,struct pv_record *record){
    if(n<0||n>65535){errno=ERANGE;return -1;}
    char path[96],value[64];snprintf(path,sizeof(path),"/sys/devices/virtual/block/loop%d/dev",n);
    record->loop_operation=PV_LOOP_SYSFS_OPEN;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    record->loop_operation=PV_LOOP_SYSFS_READ;
    struct statfs fs;int error=0;ssize_t bytes=-1;
    if(fstatfs(fd,&fs))error=errno;
    else if((unsigned long)fs.f_type!=0x62656572UL)error=EXDEV; /* SYSFS_MAGIC */
    else {bytes=read(fd,value,sizeof(value)-1);if(bytes<0)error=errno;else if(!bytes||bytes==(ssize_t)sizeof(value)-1)error=EPROTO;}
    close(fd);if(error){errno=error;return -1;}
    value[bytes]=0;error=pv_loop_parse(value,device);if(error){errno=error;return -1;}
    record->loop_expected_major=(int)major(*device);record->loop_expected_minor=(int)minor(*device);return 0;
}
static int pv_loop_node(int n,int flags,struct pv_record *record){
    record->loop_probe_number=n;record->loop_actual_major=-1;record->loop_actual_minor=-1;
    record->loop_expected_major=-1;record->loop_expected_minor=-1;
    dev_t expected;if(pv_loop_device(n,&expected,record))return -1;
    char path[64];snprintf(path,sizeof(path),"/dev/block/loop%d",n);
    record->loop_operation=PV_LOOP_NODE_OPEN;
    int fd=open(path,flags|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0&&errno==ENOENT){snprintf(path,sizeof(path),"/dev/loop%d",n);fd=open(path,flags|O_CLOEXEC|O_NOFOLLOW);}
    if(fd<0)return -1;
    struct stat info;int error=0;record->loop_operation=PV_LOOP_NODE_STAT;
    if(fstat(fd,&info))error=errno;
    else {record->loop_operation=PV_LOOP_NODE_IDENTITY;record->loop_actual_major=(int)major(info.st_rdev);record->loop_actual_minor=(int)minor(info.st_rdev);
        if(!S_ISBLK(info.st_mode)||info.st_rdev!=expected)error=ENODEV;}
    if(error){close(fd);errno=error;return -1;}return fd;
}
static int pv_loop_configure(int fd,int backing,uint64_t offset,uint64_t size){
    struct loop_config config={.fd=(uint32_t)backing,.info={.lo_offset=offset,.lo_sizelimit=size,.lo_flags=LO_FLAGS_READ_ONLY|LO_FLAGS_AUTOCLEAR}};
    return ioctl(fd,LOOP_CONFIGURE,&config);
}
static int pv_loop_attach(int backing,uint64_t offset,uint64_t size,int *number,struct pv_record *record){
    record->loop_operation=PV_LOOP_CONTROL_OPEN;
    int control=open("/dev/loop-control",O_RDWR|O_CLOEXEC|O_NOFOLLOW),preferred=-1;
    if(control<0&&errno==ENOENT)control=open("/dev/block/loop-control",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if(control<0){record->loop_control_errno=errno;if(errno!=ENOENT)return -1;}
    else {
        struct stat info;record->loop_operation=PV_LOOP_CONTROL_IDENTITY;
        int error=0;
        if(fstat(control,&info))error=errno;
        else if(!S_ISCHR(info.st_mode)||major(info.st_rdev)!=10||minor(info.st_rdev)!=237)error=ENODEV;
        if(!error){record->loop_operation=PV_LOOP_GET_FREE;preferred=ioctl(control,LOOP_CTL_GET_FREE);if(preferred<0)error=errno;else if(preferred>65535){preferred=-1;error=ERANGE;}}
        close(control);record->loop_control_errno=error;
        /* Permission/type errors must not be hidden by another allocation path. */
        if(error){errno=error;return -1;}
    }
    record->loop_preferred=preferred;
    if(preferred>=0){
        for(int attempt=0;attempt<21;attempt++){
            int fd=pv_loop_node(preferred,O_RDWR,record);
            if(fd>=0){record->loop_candidates++;record->loop_operation=PV_LOOP_CONFIGURE;if(!pv_loop_configure(fd,backing,offset,size)){*number=preferred;return fd;}int error=errno;close(fd);record->loop_node_errno=error;if(error!=EBUSY){errno=error;return -1;}break;}
            record->loop_node_errno=errno;if(errno!=ENOENT)return -1;
            if(attempt<20)usleep(50000);
        }
    }
    /* Bounded existing-node fallback; never create nodes, clear another loop,
       or fall back to legacy non-atomic SET_FD/SET_STATUS configuration. */
    int last_error=record->loop_node_errno==EBUSY?EBUSY:ENODEV;
    for(int n=0;n<1024;n++){
        if(n==preferred)continue;
        int fd=pv_loop_node(n,O_RDWR,record);
        if(fd<0){int error=errno;if(error==ENOENT)continue;errno=error;return -1;}
        record->loop_candidates++;record->loop_operation=PV_LOOP_CONFIGURE;
        if(!pv_loop_configure(fd,backing,offset,size)){*number=n;return fd;}
        last_error=errno;close(fd);
        if(last_error!=EBUSY){errno=last_error;return -1;}
    }
    errno=last_error;return -1;
}
static int pv_loop_released(int n){struct pv_record record={0};int fd=pv_loop_node(n,O_RDONLY,&record);if(fd<0)return 0;struct loop_info64 info;int rc=ioctl(fd,LOOP_GET_STATUS64,&info),error=errno;close(fd);return rc<0&&error==ENXIO;}
static int pv_zero_caps(void){struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};struct __user_cap_data_struct d[2]={{0}};if(syscall(SYS_capget,&h,d))return 0;return !(d[0].effective|d[0].permitted|d[0].inheritable|d[1].effective|d[1].permitted|d[1].inheritable);}
static int pv_limit(int resource,rlim_t value){struct rlimit r={value,value};return setrlimit(resource,&r);}
static int pv_exec_guest(void){
    /* Android's direct linker entry accepts PROGRAM, not glibc's
       --library-path option. Supply a fixed path through its own environment. */
    /* Force the mksh builtin: external printf would require forbidden fork. */
    char *args[]={"/apex/com.android.runtime/bin/linker64","/system/bin/sh","-c","builtin echo PD2425_GSI_SHELL_OK",NULL};
    char *env[]={"PATH=/system/bin","HOME=/","ANDROID_ROOT=/system","ANDROID_RUNTIME_ROOT=/apex/com.android.runtime","LD_LIBRARY_PATH=/apex/com.android.runtime/lib64/bionic:/system/lib64",NULL};
    if(pv_service_mode>=2){char owner[64];snprintf(owner,sizeof(owner),"PD2425_OWNER_PID=%ld",(long)getppid());char *run[]={(char*)pv_kind()->path,NULL};char *service_env[]={env[0],env[1],env[2],env[3],owner,pv_service_mode==3?"PD2425_SERVICE_KIND=hwservicemanager":"PD2425_SERVICE_KIND=servicemanager",NULL};return execve(run[0],run,service_env);}
    if(pv_service_mode==1){char *list[]={args[0],"--list","/system/bin/servicemanager",NULL};return execve(list[0],list,env);}
    return execve(args[0],args,env);
}
static void pv_worker(int image,int metadata,int output,int owner_fd,const char *target,const struct stat *parent_mnt,const struct stat *parent_net){
    struct pv_record r={.loops={-1,-1},.loop_preferred=-1,.loop_probe_number=-1,.loop_actual_major=-1,.loop_actual_minor=-1,.loop_expected_major=-1,.loop_expected_minor=-1};int context_fd=-1;int loop[2]={-1,-1};char path[256],digest[65];
#define PV_STEP(n,call) do{r.stage=n;if((call)<0){r.error=errno?errno:EIO;goto failed;}}while(0)
#define PV_CHECK(n,code) do{r.stage=n;int e=(code);if(e){r.error=e;goto failed;}}while(0)
    PV_STEP(1,prctl(PR_SET_PDEATHSIG,SIGKILL));if(pd_wait_pidfd(owner_fd,0)!=ETIMEDOUT){r.error=ECHILD;goto failed;}
    PV_STEP(2,unshare(CLONE_NEWNS|CLONE_NEWNET));PV_STEP(2,mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL));
    struct stat own;PV_STEP(2,stat("/proc/self/ns/mnt",&own));if(pd_same_inode(&own,parent_mnt)){r.error=EXDEV;goto failed;}PV_STEP(2,stat("/proc/self/ns/net",&own));if(pd_same_inode(&own,parent_net)){r.error=EXDEV;goto failed;}r.namespaces_private=1;
    PV_STEP(3,loop[0]=pv_loop_attach(image,0,PV_IMAGE_BYTES,&r.loops[0],&r));r.loop_count=1;
    snprintf(path,sizeof(path),"/proc/self/fd/%d",loop[0]);PV_STEP(4,mount(path,target,"ext4",MS_RDONLY|MS_NOSUID|MS_NODEV,"noload"));
    int root=-1,apex=-1;PV_STEP(5,root=open(target,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
    PV_STEP(5,apex=pv_inside(root,"system/apex/com.android.runtime.apex",O_RDONLY));
    PV_CHECK(5,pv_exact_file(apex,PV_APEX_BYTES,PV_APEX_SHA,digest));PV_CHECK(5,pv_ext4(apex,PV_PAYLOAD_OFFSET));
    PV_STEP(6,loop[1]=pv_loop_attach(apex,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&r.loops[1],&r));r.loop_count=2;
    /* Never traverse a GSI-controlled symlink while privileged: resolve mount
       targets as directory FDs with IN_ROOT|NO_SYMLINKS and use those FDs. */
    struct open_how dirhow={.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC,.resolve=RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS};
    int apexdir=(int)syscall(SYS_openat2,root,"apex",&dirhow,sizeof(dirhow));PV_STEP(7,apexdir);
    snprintf(path,sizeof(path),"/proc/self/fd/%d",apexdir);PV_STEP(7,mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV,"size=1m,mode=0755"));close(apexdir);
    int writable_apex=pv_inside(root,"apex",O_RDONLY|O_DIRECTORY);PV_STEP(7,writable_apex);if(pv_service_mode>=2){const char label[]="u:object_r:apex_mnt_dir:s0";PV_STEP(7,fsetxattr(writable_apex,"security.selinux",label,sizeof(label),0));}PV_STEP(7,mkdirat(writable_apex,"com.android.runtime",0755));
    char mountpoint[256],source[64];snprintf(mountpoint,sizeof(mountpoint),"/proc/self/fd/%d/com.android.runtime",writable_apex);snprintf(source,sizeof(source),"/proc/self/fd/%d",loop[1]);
    PV_STEP(7,mount(source,mountpoint,"ext4",MS_RDONLY|MS_NOSUID|MS_NODEV,"noload"));close(writable_apex);
    if(pv_service_mode){if(pv_service_mode>=2){PV_STEP(15,sm_prepare_fs(root,pv_helper_fd,PD_SM_CHECK_BYTES,PD_SM_CHECK_SHA,&r.sm,&context_fd,pv_kind()));PV_STEP(14,pv_create_linkerconfig_body(root,pv_config(),pv_config_bytes(),1));}else PV_STEP(14,pv_create_linkerconfig(root));r.linkerconfig_readonly=1;}
    int linker=-1,shell=-1;PV_STEP(8,linker=pv_inside(root,pv_service_mode>=2?"system/bin/bootstrap/linker64":"apex/com.android.runtime/bin/linker64",O_RDONLY));PV_CHECK(8,pv_elf64(linker));
    unsigned char capability[64];errno=0;ssize_t capsize=fgetxattr(linker,"security.capability",capability,sizeof(capability));if(capsize>=0||(errno!=ENODATA&&errno!=ENOTSUP)){r.error=EACCES;goto failed;}
    PV_STEP(8,shell=pv_inside(root,pv_service_mode?pv_kind()->path+1:"system/bin/sh",O_RDONLY));PV_CHECK(8,pv_elf64(shell));
    if(pv_service_mode>=2){struct stat info;PV_STEP(8,fstat(shell,&info));r.sm.service_dev=info.st_dev;r.sm.service_ino=info.st_ino;PV_STEP(8,fstat(linker,&info));r.sm.linker_dev=info.st_dev;r.sm.linker_ino=info.st_ino;}
    if(pv_service_mode>=2)sm_capture_exec(shell,linker,&r.exec,pv_kind());
    close(linker);close(shell);
    /* Root/runtime remain immutable. Smoke adds private tmpfs, own proc attrs
       and a real readonly SELinux view with two query-only RW aliases. */
    PV_STEP(9,fchdir(root));PV_STEP(9,chroot("."));PV_STEP(9,chdir("/"));
    PV_STEP(10,pv_limit(RLIMIT_CORE,0));PV_STEP(10,pv_limit(RLIMIT_CPU,5));/* Android Scudo reserves several GiB of VA without committing that RAM.
       A tiny AS limit breaks libc before main. Fork is denied by seccomp;
       NPROC=0 would also make exec fail after the UID transition. */
    PV_STEP(10,pv_limit(RLIMIT_AS,(rlim_t)64*1024*1024*1024));
    PV_STEP(10,prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0));PV_STEP(10,setgroups(0,NULL));PV_STEP(10,setresgid(pv_service_mode>=2?1000:65534,pv_service_mode>=2?1000:65534,pv_service_mode>=2?1000:65534));PV_STEP(10,setresuid(pv_service_mode>=2?1000:65534,pv_service_mode>=2?1000:65534,pv_service_mode>=2?1000:65534));
    struct __user_cap_header_struct caph={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};struct __user_cap_data_struct capd[2]={{0}};PV_STEP(10,(int)syscall(SYS_capset,&caph,capd));
    r.uid=getuid();r.gid=getgid();r.caps_zero=pv_zero_caps();if(r.uid!=(pv_service_mode>=2?1000:65534)||r.gid!=(pv_service_mode>=2?1000:65534)||!r.caps_zero){r.error=EPERM;goto failed;}
    /* UID changes clear PDEATHSIG. Re-arm, then check inherited owner pidfd. */
    PV_STEP(10,prctl(PR_SET_PDEATHSIG,SIGKILL));if(pd_wait_pidfd(owner_fd,0)!=ETIMEDOUT){r.error=ECHILD;goto failed;}
    if(pv_service_mode>=2){
        const char *domain=pv_kind()->domain;r.stage=16;
        /* Preserve owned loop/FS evidence even if the domain cannot use the setup pipe. */
        ssize_t interim=write(metadata,&r,sizeof(r));if(interim!=(ssize_t)sizeof(r))_exit(42);
        ssize_t count=write(context_fd,domain,strlen(domain));if(count!=(ssize_t)strlen(domain)){r.error=count<0?errno:EPROTO;goto failed;}close(context_fd);context_fd=-1;
        char current[128];PV_CHECK(16,read_text("/proc/self/attr/exec",current,sizeof(current)));current[strcspn(current,"\n")]=0;
        if(strcmp(current,domain)||!pv_zero_caps()){r.error=EPERM;goto failed;}r.sm.context_verified=1;
        PV_STEP(16,prctl(PR_SET_PDEATHSIG,SIGKILL));if(pd_wait_pidfd(owner_fd,0)!=ETIMEDOUT){r.error=ECHILD;goto failed;}
    }
    PV_STEP(11,dup2(output,1));PV_STEP(11,dup2(output,2));
    /* stdin is a pipe with no writer (EOF). Keep metadata only until exec. */
    int eof[2];PV_STEP(11,pipe2(eof,O_CLOEXEC));close(eof[1]);PV_STEP(11,dup2(eof[0],0));close(eof[0]);
    int meta_copy=fcntl(metadata,F_DUPFD_CLOEXEC,3);PV_STEP(11,meta_copy);if(meta_copy!=3){PV_STEP(11,dup3(meta_copy,3,O_CLOEXEC));close(meta_copy);}metadata=3;
    PV_STEP(11,(int)syscall(SYS_close_range,4U,UINT_MAX,0U));
    PV_STEP(12,prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));r.nnp=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0);if(r.nnp!=1){r.error=EPROTO;goto failed;}
    PV_STEP(12,pv_service_mode>=2?sm_install_policy():pv_install_filter());PV_STEP(12,pv_test_filter());r.filter_verified=5;r.prepared=1;r.stage=13;
    /* This fixed record is from trusted setup. FD3 closes on exec, so guest
       stdout cannot forge privileged setup metadata. No arbitrary shell input. */
    if(write(metadata,&r,sizeof(r))!=(ssize_t)sizeof(r))_exit(42);
    pv_exec_guest();
    r.error=errno;r.prepared=0;{ssize_t sent=write(metadata,&r,sizeof(r));(void)sent;}_exit(43);
failed:
    {ssize_t sent=write(metadata,&r,sizeof(r));(void)sent;}_exit(40);
#undef PV_STEP
#undef PV_CHECK
}
static int pv_parent_same(const struct stat *mnt,const struct stat *net,const struct stat *root){struct stat now;return !stat("/proc/self/ns/mnt",&now)&&pd_same_inode(mnt,&now)&&!stat("/proc/self/ns/net",&now)&&pd_same_inode(net,&now)&&!stat("/",&now)&&pd_same_inode(root,&now);}
static int pv_run(int image,struct pv_result *r){
    char temp[]="/data/local/tmp/gsionlocked_preview_XXXXXX";int metadata[2]={-1,-1},output[2]={-1,-1},owner=-1,task=-1,changed_chld=0;struct sigaction old_chld,normal={.sa_handler=SIG_DFL};sigemptyset(&normal.sa_mask);pid_t child=-1;struct stat mnt,net,root;
    r->stage="parent_snapshot";if(stat("/proc/self/ns/mnt",&mnt)||stat("/proc/self/ns/net",&net)||stat("/",&root)){r->error=errno;return 40;}
    r->stage="temporary_directory";if(!mkdtemp(temp)){r->error=errno;return 40;}
    if(sigaction(SIGCHLD,&normal,&old_chld)){r->error=errno;goto done;}changed_chld=1;
    if(pipe2(metadata,O_CLOEXEC|O_NONBLOCK)||pipe2(output,O_CLOEXEC|O_NONBLOCK)){r->error=errno;goto done;}
    /* Make only the child's write ends blocking; output reader stays bounded. */
    if(fcntl(metadata[1],F_SETFL,0)||fcntl(output[1],F_SETFL,0)){r->error=errno;goto done;}
    owner=(int)syscall(SYS_pidfd_open,getpid(),0);if(owner<0){r->error=errno;goto done;}
    r->stage="fork";child=fork();if(child<0){r->error=errno;goto done;}
    if(!child){close(metadata[0]);close(output[0]);pv_worker(image,metadata[1],output[1],owner,temp,&mnt,&net);_exit(44);}
    r->spawned=1;close(metadata[1]);metadata[1]=-1;close(output[1]);output[1]=-1;
    task=(int)syscall(SYS_pidfd_open,child,0);if(task<0){r->error=errno;goto done;}
    r->stage="guest_execution";size_t used=0;int exited=0;struct timespec start,now;if(clock_gettime(CLOCK_MONOTONIC,&start)){r->error=errno;goto done;}
    while(!exited){
        struct pollfd fds[]={{metadata[0],POLLIN,0},{output[0],POLLIN,0},{task,POLLIN,0}};int rc=poll(fds,3,100);if(rc<0&&errno!=EINTR){r->error=errno;break;}
        if(fds[0].revents&POLLIN){ssize_t n=read(metadata[0],&r->child,sizeof(r->child));if(n!=(ssize_t)sizeof(r->child)){r->error=EPROTO;break;}r->metadata_received=1;}
        if(fds[1].revents&POLLIN){char b[1024];ssize_t n=read(output[0],b,sizeof(b));if(n>0){size_t copy=(size_t)n;if(copy>sizeof(r->output)-1-used)copy=sizeof(r->output)-1-used;memcpy(r->output+used,b,copy);used+=copy;r->output[used]=0;}}
        if(pv_service_mode>=2&&r->metadata_received&&r->child.prepared&&!(fds[2].revents&POLLIN)){
            int threads=0;int identity=sm_check_process(child,&r->child.sm,&threads,pv_kind());if(threads>r->thread_peak)r->thread_peak=threads;if(identity==E2BIG){r->error=E2BIG;break;}
            if(!identity){r->ping_errno=sm_ping_process(child,&r->child.sm,pv_kind());if(!r->ping_errno){int after=sm_check_process(child,&r->child.sm,&threads,pv_kind());if(threads>r->thread_peak)r->thread_peak=threads;if(after==E2BIG){r->error=E2BIG;break;}if(!after){r->identity_verified=r->ping_passed=r->owned_stop=1;break;}}}
            else r->ping_errno=identity;
        }
        exited=fds[2].revents&POLLIN;clock_gettime(CLOCK_MONOTONIC,&now);if(now.tv_sec-start.tv_sec>=20){r->error=ETIMEDOUT;break;}
    }
    /* Drain output after exit, without waiting on any possible writer. */
    for(int chunks=0;chunks<128;chunks++){char b[1024];ssize_t n=read(output[0],b,sizeof(b));if(n<=0)break;size_t copy=(size_t)n;if(copy>sizeof(r->output)-1-used)copy=sizeof(r->output)-1-used;memcpy(r->output+used,b,copy);used+=copy;r->output[used]=0;}
    for(int records=0;records<2;records++){ssize_t n=read(metadata[0],&r->child,sizeof(r->child));if(n==(ssize_t)sizeof(r->child))r->metadata_received=1;else break;}
done:
    /* Trusted setup creates one process. Smoke permits exact pthread clones
       in its TGID only; pidfd SIGKILL terminates that entire thread group.
       Never signal a process outside this unreaped owned PID. */
    if(child>1){if(task>=0)syscall(SYS_pidfd_send_signal,task,SIGKILL,NULL,0);else kill(child,SIGKILL);int status=0;pid_t n=0;for(int t=0;t<100;t++){n=waitpid(child,&status,WNOHANG);if(n==child||(n<0&&errno!=EINTR))break;usleep(50000);}if(n==child){r->reaped=1;r->exit_code=WIFEXITED(status)?WEXITSTATUS(status):-1;r->signal=WIFSIGNALED(status)?WTERMSIG(status):0;}else r->cleanup_error=n==0?ETIMEDOUT:errno;}
    for(int n=0;n<2;n++){if(metadata[n]>=0)close(metadata[n]);if(output[n]>=0)close(output[n]);}if(task>=0)close(task);if(owner>=0)close(owner);
    r->loops_released=1;
    if(r->spawned&&!r->metadata_received)r->loops_released=0;
    if(r->metadata_received){if(r->child.loop_count<0||r->child.loop_count>2){r->cleanup_error=EPROTO;r->loops_released=0;}else for(int n=0;n<r->child.loop_count;n++){int released=0;for(int t=0;t<40;t++){if(pv_loop_released(r->child.loops[n])){released=1;break;}usleep(50000);}if(!released)r->loops_released=0;}}
    if(changed_chld&&sigaction(SIGCHLD,&old_chld,NULL))r->cleanup_error=errno;
    if(rmdir(temp))r->cleanup_error=errno;else r->temp_removed=1;
    r->parent_unchanged=pv_parent_same(&mnt,&net,&root);
    if(pv_service_mode>=2){
        char enforcing[16];r->host_enforcing=!read_text("/sys/fs/selinux/enforce",enforcing,sizeof(enforcing))&&enforcing[0]=='1';
        if(!r->error&&(!r->metadata_received||r->child.error||!r->child.prepared||!r->child.linkerconfig_readonly||!r->child.sm.binder_verified||!r->child.sm.selinux_verified||!r->child.sm.context_verified||!r->child.sm.entry_verified||!r->child.sm.self_proc_only||!r->child.sm.helper_verified||!r->identity_verified||!r->ping_passed||!r->owned_stop||!r->reaped||r->signal!=SIGKILL||!r->host_enforcing||!strstr(r->output,pv_kind()->marker)))r->error=r->child.error?r->child.error:EPROTO;
        for(int n=0;n<3;n++)if(r->child.sm.host_present[n]){char path[32];struct stat node;snprintf(path,sizeof(path),"/dev/%s",pd_binder_names[n]);if(stat(path,&node)||(uint64_t)node.st_dev!=r->child.sm.host_dev[n]||(uint64_t)node.st_ino!=r->child.sm.host_ino[n]||(uint64_t)node.st_rdev!=r->child.sm.host_rdev[n])r->cleanup_error=EXDEV;}
    }else if(!r->error&&(!r->metadata_received||r->child.error||!r->child.prepared||r->exit_code||r->signal||!(pv_service_mode?(r->child.linkerconfig_readonly&&strstr(r->output,"libbinder.so")&&strstr(r->output,"libc.so")):(strstr(r->output,"PD2425_GSI_SHELL_OK\n")!=NULL))))r->error=r->child.error?r->child.error:EPROTO;
    if(!r->parent_unchanged||!r->loops_released||!r->temp_removed)r->cleanup_error=r->cleanup_error?r->cleanup_error:EPROTO;
    if(!r->error&&!r->cleanup_error)r->stage="complete";
    return r->error||r->cleanup_error?40:0;
}
static int pv_main(const char *path){
    struct sigaction alarm_action={.sa_handler=SIG_DFL};sigemptyset(&alarm_action.sa_mask);sigaction(SIGALRM,&alarm_action,NULL);sigset_t alarms;sigemptyset(&alarms);sigaddset(&alarms,SIGALRM);sigprocmask(SIG_UNBLOCK,&alarms,NULL);alarm(300);
    char device[PROP_VALUE_MAX],sdk[PROP_VALUE_MAX],abi[PROP_VALUE_MAX],fp[PROP_VALUE_MAX];__system_property_get("ro.product.device",device);__system_property_get("ro.build.version.sdk",sdk);__system_property_get("ro.product.cpu.abi",abi);__system_property_get("ro.build.fingerprint",fp);
    struct pv_result r={.exit_code=-1,.stage="host_identity",.child={.loop_preferred=-1,.loop_probe_number=-1,.loop_actual_major=-1,.loop_actual_minor=-1,.loop_expected_major=-1,.loop_expected_minor=-1}};int rc=40,image=-1;
    if(!pd2425_identity(device,sdk,abi,fp)){r.error=EINVAL;rc=31;goto report;}
    if(getuid()!=0){r.error=EPERM;goto report;}
    char value[64];r.stage="selinux";if(read_text("/sys/fs/selinux/enforce",value,sizeof(value))||(strcmp(value,"1")&&strcmp(value,"1\n"))){r.error=EPERM;goto report;}
    r.stage="temperature";int temperature=0;if(read_text("/sys/class/power_supply/battery/temp",value,sizeof(value))||sscanf(value,"%d",&temperature)!=1||temperature< -200||temperature>380){r.error=ERANGE;goto report;}
    r.stage="image_open";image=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(image<0){r.error=errno;goto report;}
    r.stage="image_sha256";puts("PREVIEW_STAGE=image_sha256");fflush(stdout);r.error=pv_exact_file(image,PV_IMAGE_BYTES,PV_IMAGE_SHA,r.digest);if(r.error)goto report;r.error=pv_ext4(image,0);if(r.error)goto report;
    if(pv_service_mode>=2){
        r.stage="packaged_helper";if(strlen(PD_SM_CHECK_SHA)!=64||!PD_SM_CHECK_BYTES){r.error=ENOTSUP;goto report;}
        char executable[4096];ssize_t length=readlink("/proc/self/exe",executable,sizeof(executable)-1);if(length<=0||length>=(ssize_t)sizeof(executable)-1){r.error=ENOENT;goto report;}executable[length]=0;
        char *last=strrchr(executable,'/');if(!last){r.error=EINVAL;goto report;}*last=0;int directory=open(executable,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(directory<0){r.error=errno;goto report;}
        pv_helper_fd=openat(directory,"libpd2425_sm_check.so",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);int saved=errno;close(directory);if(pv_helper_fd<0){r.error=saved;goto report;}
        char helper_digest[65];r.error=pv_exact_file(pv_helper_fd,PD_SM_CHECK_BYTES,PD_SM_CHECK_SHA,helper_digest);if(!r.error)r.error=pv_elf64(pv_helper_fd);if(r.error)goto report;
    }
    rc=pv_run(image,&r);
report:
    if(image>=0)close(image);
    if(pv_helper_fd>=0){close(pv_helper_fd);pv_helper_fd=-1;}
    printf("{\"schema\":1,\"component\":\"%s\",\"runtime_ready\":false,\"guest_boot_complete\":false,\"host_services_changed\":false,\"uid\":",pv_service_mode>=2?(pv_service_mode==3?"hwservice-smoke-preview":"service-smoke-preview"):pv_service_mode?"service-loader-preview":"gsi-preview");printf("%lu,\"preview_passed\":%s,\"fingerprint\":",(unsigned long)getuid(),rc==0?"true":"false");json_string(fp);
    fputs(",\"boot_id\":",stdout);json_file("/proc/sys/kernel/random/boot_id");fputs(",\"image_sha256\":",stdout);json_string(r.digest);fputs(",\"stage\":",stdout);json_string(r.stage);
    int stage=r.child.stage>=0&&r.child.stage<(int)(sizeof(pv_stages)/sizeof(pv_stages[0]))?r.child.stage:0;fputs(",\"child_stage\":",stdout);json_string(pv_stages[stage]);
    printf(",\"errno\":%d,\"child_errno\":%d,\"cleanup_errno\":%d,\"spawned\":%d,\"reaped\":%d,\"exit_code\":%d,\"signal\":%d,\"prepared\":%s,\"guest_uid\":%d,\"guest_gid\":%d,\"capabilities_zero\":%s,\"no_new_privs\":%d,\"filter_verified\":%d,\"namespaces_private\":%s,\"metadata_received\":%s,\"parent_unchanged\":%s,\"loops_released\":%s,\"temporary_directory_removed\":%s,\"output\":",r.error,r.child.error,r.cleanup_error,r.spawned,r.reaped,r.exit_code,r.signal,r.child.prepared?"true":"false",r.child.uid,r.child.gid,r.child.caps_zero?"true":"false",r.child.nnp,r.child.filter_verified,r.child.namespaces_private?"true":"false",r.metadata_received?"true":"false",r.parent_unchanged?"true":"false",r.loops_released?"true":"false",r.temp_removed?"true":"false");json_string(r.output);
    printf(",\"loop_control_errno\":%d,\"loop_node_errno\":%d,\"loop_candidates\":%d",r.child.loop_control_errno,r.child.loop_node_errno,r.child.loop_candidates);
    printf(",\"loop_preferred\":%d,\"loop_probe_number\":%d,\"loop_actual_major\":%d,\"loop_actual_minor\":%d,\"loop_expected_major\":%d,\"loop_expected_minor\":%d,\"loop_operation\":",r.child.loop_preferred,r.child.loop_probe_number,r.child.loop_actual_major,r.child.loop_actual_minor,r.child.loop_expected_major,r.child.loop_expected_minor);
    json_string(r.child.loop_operation>=0&&r.child.loop_operation<(int)(sizeof(pv_loop_operations)/sizeof(pv_loop_operations[0]))?pv_loop_operations[r.child.loop_operation]:"invalid");
    printf(",\"service_main_executed\":%s,\"linkerconfig_readonly\":%s,\"target\":",pv_service_mode>=2?(r.ping_passed?"true":"null"):"false",r.child.linkerconfig_readonly?"true":"false");json_string(pv_service_mode?pv_kind()->path:"/system/bin/sh");
    char config_hash[65];struct pv_sha config_sha;pv_sha_init(&config_sha);pv_sha_update(&config_sha,pv_config(),pv_config_bytes());pv_sha_final(&config_sha,config_hash);
    fputs(",\"bootstrap_linkerconfig_sha256\":",stdout);json_string(pv_service_mode?config_hash:"");
    printf(",\"binder_private\":%s,\"selinux_view_verified\":%s,\"self_proc_only\":%s,\"packaged_helper_verified\":%s,\"service_domain_verified\":%s,\"process_identity_verified\":%s,\"context_manager_ping_passed\":%s,\"owned_stop\":%s,\"host_enforcing_preserved\":%s,\"ping_errno\":%d",r.child.sm.binder_verified?"true":"false",r.child.sm.selinux_verified?"true":"false",r.child.sm.self_proc_only?"true":"false",r.child.sm.helper_verified?"true":"false",(pv_service_mode>=2?r.identity_verified:r.child.sm.context_verified)?"true":"false",r.identity_verified?"true":"false",r.ping_passed?"true":"false",r.owned_stop?"true":"false",r.host_enforcing?"true":"false",r.ping_errno);
    printf(",\"entry_adapted\":%s,\"exec_context_requested\":%s",r.child.sm.entry_verified?"true":"false",r.child.sm.context_verified?"true":"false");
    fputs(",\"service_entry_sha256\":",stdout);json_string(pv_service_mode>=2?(pv_service_mode==3?HW_ENTRY_PATCHED_SHA:SM_ENTRY_PATCHED_SHA):"");
    fputs(",\"ping_method\":",stdout);json_string(pv_service_mode==3?"HIDL IBase.ping":"Binder PING_TRANSACTION");
    sm_json_exec(&r.child.exec);
    printf(",\"thread_limit\":%d,\"observed_thread_peak\":%d,\"pthread_clone_flags\":%u",pv_service_mode>=2?SM_MAX_THREADS:0,r.thread_peak,pv_service_mode>=2?(unsigned)SM_THREAD_FLAGS:0);
    fputs(",\"binder_driver\":",stdout);json_string(pv_service_mode>=2?pv_kind()->driver:"");fputs(",\"service_domain\":",stdout);json_string(pv_service_mode>=2?pv_kind()->domain:"");
    int fs_stage=r.child.sm.stage>=0&&r.child.sm.stage<(int)(sizeof(sm_fs_stages)/sizeof(sm_fs_stages[0]))?r.child.sm.stage:0;
    fputs(",\"service_filesystem_stage\":",stdout);json_string(sm_fs_stages[fs_stage]);
    fputs(",\"packaged_helper_sha256\":",stdout);json_string(pv_service_mode>=2?PD_SM_CHECK_SHA:"");
    fputs(",\"scope\":\"Pinned upstream shell, loader or bounded private service manager. Capless UID65534 for loader/shell; UID1000 and the selected real service-manager domain for smoke. Private Binder, readonly policy except access/context queries, own proc attr only. Default-deny, no fork/network/host services/HAL/framework or partition writes.\"}\n",stdout);return rc;
}
int main(int argc,char **argv){
    if(argc==3&&!strcmp(argv[1],"--smoke-hwservicemanager")){pv_service_mode=3;return pv_main(argv[2]);}
    if(argc==3&&!strcmp(argv[1],"--smoke-servicemanager")){pv_service_mode=2;return pv_main(argv[2]);}
    if(argc==3&&!strcmp(argv[1],"--preview-service-loader")){pv_service_mode=1;return pv_main(argv[2]);}
    if(argc==3&&!strcmp(argv[1],"--preview-gsi"))return pv_main(argv[2]);
    if(argc==3&&!strcmp(argv[1],"--verify-image")){int fd=open(argv[2],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 40;char sha[65]={0};int error=pv_exact_file(fd,PV_IMAGE_BYTES,PV_IMAGE_SHA,sha);if(!error)error=pv_ext4(fd,0);close(fd);printf("image_sha256=%s\nerrno=%d\n",sha,error);return error?40:0;}
    return pd_diagnostic_main(argc,argv);
}
