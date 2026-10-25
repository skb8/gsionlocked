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
struct pv_record {int prepared,error,stage,uid,gid,caps_zero,nnp,filter_verified,namespaces_private,loop_count,loops[2],loop_control_errno,loop_node_errno,loop_candidates;};
struct pv_result {int error,cleanup_error,spawned,reaped,exit_code,signal,metadata_received,parent_unchanged,loops_released,temp_removed;const char *stage;char digest[65],output[8193];struct pv_record child;};
static const char *pv_stages[]={"none","parent_death","private_namespaces","image_loop","image_mount","runtime_apex","runtime_loop","runtime_mount","elf_validation","chroot","drop_privileges","close_fds","seccomp","exec"};
static int pv_inside(int root,const char *path,int flags){struct open_how how={.flags=(uint64_t)(flags|O_CLOEXEC),.resolve=RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS};return (int)syscall(SYS_openat2,root,path,&how,sizeof(how));}
/* GET_FREE may return a kernel loop whose /dev node ueventd has not created.
   Android may also omit loop-control entirely. Existing block nodes are safe
   candidates only after exact device validation and atomic LOOP_CONFIGURE. */
static int pv_loop_node(int n,int flags){
    char path[64];snprintf(path,sizeof(path),"/dev/block/loop%d",n);
    int fd=open(path,flags|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0&&errno==ENOENT){snprintf(path,sizeof(path),"/dev/loop%d",n);fd=open(path,flags|O_CLOEXEC|O_NOFOLLOW);}
    if(fd<0)return -1;
    struct stat info;int error=0;
    if(fstat(fd,&info))error=errno;
    else if(!S_ISBLK(info.st_mode)||major(info.st_rdev)!=7||minor(info.st_rdev)!=(unsigned)n)error=ENODEV;
    if(error){close(fd);errno=error;return -1;}return fd;
}
static int pv_loop_configure(int fd,int backing,uint64_t offset,uint64_t size){
    struct loop_config config={.fd=(uint32_t)backing,.info={.lo_offset=offset,.lo_sizelimit=size,.lo_flags=LO_FLAGS_READ_ONLY|LO_FLAGS_AUTOCLEAR}};
    return ioctl(fd,LOOP_CONFIGURE,&config);
}
static int pv_loop_attach(int backing,uint64_t offset,uint64_t size,int *number,struct pv_record *record){
    int control=open("/dev/loop-control",O_RDWR|O_CLOEXEC|O_NOFOLLOW),preferred=-1;
    if(control<0&&errno==ENOENT)control=open("/dev/block/loop-control",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if(control<0){record->loop_control_errno=errno;if(errno!=ENOENT)return -1;}
    else {
        struct stat info;
        int error=0;
        if(fstat(control,&info))error=errno;
        else if(!S_ISCHR(info.st_mode)||major(info.st_rdev)!=10||minor(info.st_rdev)!=237)error=ENODEV;
        if(!error){preferred=ioctl(control,LOOP_CTL_GET_FREE);if(preferred<0)error=errno;else if(preferred>65535){preferred=-1;error=ERANGE;}}
        close(control);record->loop_control_errno=error;
        /* Permission/type errors must not be hidden by another allocation path. */
        if(error){errno=error;return -1;}
    }
    if(preferred>=0){
        for(int attempt=0;attempt<21;attempt++){
            int fd=pv_loop_node(preferred,O_RDWR);
            if(fd>=0){record->loop_candidates++;if(!pv_loop_configure(fd,backing,offset,size)){*number=preferred;return fd;}int error=errno;close(fd);record->loop_node_errno=error;if(error!=EBUSY){errno=error;return -1;}break;}
            record->loop_node_errno=errno;if(errno!=ENOENT)return -1;
            if(attempt<20)usleep(50000);
        }
    }
    /* Bounded existing-node fallback; never create nodes, clear another loop,
       or fall back to legacy non-atomic SET_FD/SET_STATUS configuration. */
    int last_error=record->loop_node_errno==EBUSY?EBUSY:ENODEV;
    for(int n=0;n<1024;n++){
        if(n==preferred)continue;
        int fd=pv_loop_node(n,O_RDWR);
        if(fd<0){int error=errno;if(error==ENOENT)continue;errno=error;return -1;}
        record->loop_candidates++;
        if(!pv_loop_configure(fd,backing,offset,size)){*number=n;return fd;}
        last_error=errno;close(fd);
        if(last_error!=EBUSY){errno=last_error;return -1;}
    }
    errno=last_error;return -1;
}
static int pv_loop_released(int n){int fd=pv_loop_node(n,O_RDONLY);if(fd<0)return 0;struct loop_info64 info;int rc=ioctl(fd,LOOP_GET_STATUS64,&info),error=errno;close(fd);return rc<0&&error==ENXIO;}
static int pv_zero_caps(void){struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};struct __user_cap_data_struct d[2]={{0}};if(syscall(SYS_capget,&h,d))return 0;return !(d[0].effective|d[0].permitted|d[0].inheritable|d[1].effective|d[1].permitted|d[1].inheritable);}
static int pv_limit(int resource,rlim_t value){struct rlimit r={value,value};return setrlimit(resource,&r);}
static void pv_worker(int image,int metadata,int output,int owner_fd,const char *target,const struct stat *parent_mnt,const struct stat *parent_net){
    struct pv_record r={.loops={-1,-1}};int loop[2]={-1,-1};char path[256],digest[65];
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
    int writable_apex=pv_inside(root,"apex",O_RDONLY|O_DIRECTORY);PV_STEP(7,writable_apex);PV_STEP(7,mkdirat(writable_apex,"com.android.runtime",0755));
    char mountpoint[256],source[64];snprintf(mountpoint,sizeof(mountpoint),"/proc/self/fd/%d/com.android.runtime",writable_apex);snprintf(source,sizeof(source),"/proc/self/fd/%d",loop[1]);
    PV_STEP(7,mount(source,mountpoint,"ext4",MS_RDONLY|MS_NOSUID|MS_NODEV,"noload"));close(writable_apex);
    int linker=-1,shell=-1;PV_STEP(8,linker=pv_inside(root,"apex/com.android.runtime/bin/linker64",O_RDONLY));PV_CHECK(8,pv_elf64(linker));
    unsigned char capability[64];errno=0;ssize_t capsize=fgetxattr(linker,"security.capability",capability,sizeof(capability));if(capsize>=0||(errno!=ENODATA&&errno!=ENOTSUP)){r.error=EACCES;goto failed;}
    PV_STEP(8,shell=pv_inside(root,"system/bin/sh",O_RDONLY));PV_CHECK(8,pv_elf64(shell));close(linker);close(shell);
    /* The root and runtime are immutable mounts. No host /proc, /sys, /dev or
       data is bound. The image's empty mountpoints remain empty/read-only. */
    PV_STEP(9,fchdir(root));PV_STEP(9,chroot("."));PV_STEP(9,chdir("/"));
    PV_STEP(10,pv_limit(RLIMIT_CORE,0));PV_STEP(10,pv_limit(RLIMIT_CPU,5));/* Android Scudo reserves several GiB of VA without committing that RAM.
       A tiny AS limit breaks libc before main. Fork is denied by seccomp;
       NPROC=0 would also make exec fail after the UID transition. */
    PV_STEP(10,pv_limit(RLIMIT_AS,(rlim_t)64*1024*1024*1024));
    PV_STEP(10,prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0));PV_STEP(10,setgroups(0,NULL));PV_STEP(10,setresgid(65534,65534,65534));PV_STEP(10,setresuid(65534,65534,65534));
    struct __user_cap_header_struct caph={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};struct __user_cap_data_struct capd[2]={{0}};PV_STEP(10,(int)syscall(SYS_capset,&caph,capd));
    r.uid=getuid();r.gid=getgid();r.caps_zero=pv_zero_caps();if(r.uid!=65534||r.gid!=65534||!r.caps_zero){r.error=EPERM;goto failed;}
    /* UID changes clear PDEATHSIG. Re-arm, then check inherited owner pidfd. */
    PV_STEP(10,prctl(PR_SET_PDEATHSIG,SIGKILL));if(pd_wait_pidfd(owner_fd,0)!=ETIMEDOUT){r.error=ECHILD;goto failed;}
    PV_STEP(11,dup2(output,1));PV_STEP(11,dup2(output,2));
    /* stdin is a pipe with no writer (EOF). Keep metadata only until exec. */
    int eof[2];PV_STEP(11,pipe2(eof,O_CLOEXEC));close(eof[1]);PV_STEP(11,dup2(eof[0],0));close(eof[0]);
    int meta_copy=fcntl(metadata,F_DUPFD_CLOEXEC,3);PV_STEP(11,meta_copy);if(meta_copy!=3){PV_STEP(11,dup3(meta_copy,3,O_CLOEXEC));close(meta_copy);}metadata=3;
    PV_STEP(11,(int)syscall(SYS_close_range,4U,UINT_MAX,0U));
    PV_STEP(12,prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));r.nnp=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0);if(r.nnp!=1){r.error=EPROTO;goto failed;}
    PV_STEP(12,pv_install_filter());PV_STEP(12,pv_test_filter());r.filter_verified=5;r.prepared=1;r.stage=13;
    /* This fixed record is from trusted setup. FD3 closes on exec, so guest
       stdout cannot forge privileged setup metadata. No arbitrary shell input. */
    if(write(metadata,&r,sizeof(r))!=(ssize_t)sizeof(r))_exit(42);
    {char *args[]={"/apex/com.android.runtime/bin/linker64","--library-path","/apex/com.android.runtime/lib64/bionic:/system/lib64","/system/bin/sh","-c","printf 'PD2425_GSI_SHELL_OK\\n'",NULL};char *env[]={"PATH=/system/bin","HOME=/","ANDROID_ROOT=/system","ANDROID_RUNTIME_ROOT=/apex/com.android.runtime",NULL};execve(args[0],args,env);}
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
        exited=fds[2].revents&POLLIN;clock_gettime(CLOCK_MONOTONIC,&now);if(now.tv_sec-start.tv_sec>=20){r->error=ETIMEDOUT;break;}
    }
    /* Drain output after exit, without waiting on any possible writer. */
    for(int chunks=0;chunks<128;chunks++){char b[1024];ssize_t n=read(output[0],b,sizeof(b));if(n<=0)break;size_t copy=(size_t)n;if(copy>sizeof(r->output)-1-used)copy=sizeof(r->output)-1-used;memcpy(r->output+used,b,copy);used+=copy;r->output[used]=0;}
    for(int records=0;records<2;records++){ssize_t n=read(metadata[0],&r->child,sizeof(r->child));if(n==(ssize_t)sizeof(r->child))r->metadata_received=1;else break;}
done:
    /* No descendants are created by trusted setup; guest clone/fork/vfork are
       default-denied. Never signal a process outside this unreaped owned PID. */
    if(child>1){if(task>=0)syscall(SYS_pidfd_send_signal,task,SIGKILL,NULL,0);else kill(child,SIGKILL);int status=0;pid_t n=0;for(int t=0;t<100;t++){n=waitpid(child,&status,WNOHANG);if(n==child||(n<0&&errno!=EINTR))break;usleep(50000);}if(n==child){r->reaped=1;r->exit_code=WIFEXITED(status)?WEXITSTATUS(status):-1;r->signal=WIFSIGNALED(status)?WTERMSIG(status):0;}else r->cleanup_error=n==0?ETIMEDOUT:errno;}
    for(int n=0;n<2;n++){if(metadata[n]>=0)close(metadata[n]);if(output[n]>=0)close(output[n]);}if(task>=0)close(task);if(owner>=0)close(owner);
    r->loops_released=1;
    if(r->spawned&&!r->metadata_received)r->loops_released=0;
    if(r->metadata_received){if(r->child.loop_count<0||r->child.loop_count>2){r->cleanup_error=EPROTO;r->loops_released=0;}else for(int n=0;n<r->child.loop_count;n++){int released=0;for(int t=0;t<40;t++){if(pv_loop_released(r->child.loops[n])){released=1;break;}usleep(50000);}if(!released)r->loops_released=0;}}
    if(changed_chld&&sigaction(SIGCHLD,&old_chld,NULL))r->cleanup_error=errno;
    if(rmdir(temp))r->cleanup_error=errno;else r->temp_removed=1;
    r->parent_unchanged=pv_parent_same(&mnt,&net,&root);
    if(!r->error&&(!r->metadata_received||r->child.error||!r->child.prepared||r->exit_code||r->signal||!strstr(r->output,"PD2425_GSI_SHELL_OK\n")))r->error=r->child.error?r->child.error:EPROTO;
    if(!r->parent_unchanged||!r->loops_released||!r->temp_removed)r->cleanup_error=r->cleanup_error?r->cleanup_error:EPROTO;
    if(!r->error&&!r->cleanup_error)r->stage="complete";
    return r->error||r->cleanup_error?40:0;
}
static int pv_main(const char *path){
    struct sigaction alarm_action={.sa_handler=SIG_DFL};sigemptyset(&alarm_action.sa_mask);sigaction(SIGALRM,&alarm_action,NULL);sigset_t alarms;sigemptyset(&alarms);sigaddset(&alarms,SIGALRM);sigprocmask(SIG_UNBLOCK,&alarms,NULL);alarm(300);
    char device[PROP_VALUE_MAX],sdk[PROP_VALUE_MAX],abi[PROP_VALUE_MAX],fp[PROP_VALUE_MAX];__system_property_get("ro.product.device",device);__system_property_get("ro.build.version.sdk",sdk);__system_property_get("ro.product.cpu.abi",abi);__system_property_get("ro.build.fingerprint",fp);
    struct pv_result r={.exit_code=-1,.stage="host_identity"};int rc=40,image=-1;
    if(!pd2425_identity(device,sdk,abi,fp)){r.error=EINVAL;rc=31;goto report;}
    if(getuid()!=0){r.error=EPERM;goto report;}
    char value[64];r.stage="selinux";if(read_text("/sys/fs/selinux/enforce",value,sizeof(value))||(strcmp(value,"1")&&strcmp(value,"1\n"))){r.error=EPERM;goto report;}
    r.stage="temperature";int temperature=0;if(read_text("/sys/class/power_supply/battery/temp",value,sizeof(value))||sscanf(value,"%d",&temperature)!=1||temperature< -200||temperature>380){r.error=ERANGE;goto report;}
    r.stage="image_open";image=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(image<0){r.error=errno;goto report;}
    r.stage="image_sha256";puts("PREVIEW_STAGE=image_sha256");fflush(stdout);r.error=pv_exact_file(image,PV_IMAGE_BYTES,PV_IMAGE_SHA,r.digest);if(r.error)goto report;r.error=pv_ext4(image,0);if(r.error)goto report;
    rc=pv_run(image,&r);
report:
    if(image>=0)close(image);
    fputs("{\"schema\":1,\"component\":\"gsi-preview\",\"runtime_ready\":false,\"guest_boot_complete\":false,\"host_services_changed\":false,\"uid\":",stdout);printf("%lu,\"preview_passed\":%s,\"fingerprint\":",(unsigned long)getuid(),rc==0?"true":"false");json_string(fp);
    fputs(",\"boot_id\":",stdout);json_file("/proc/sys/kernel/random/boot_id");fputs(",\"image_sha256\":",stdout);json_string(r.digest);fputs(",\"stage\":",stdout);json_string(r.stage);
    int stage=r.child.stage>=0&&r.child.stage<(int)(sizeof(pv_stages)/sizeof(pv_stages[0]))?r.child.stage:0;fputs(",\"child_stage\":",stdout);json_string(pv_stages[stage]);
    printf(",\"errno\":%d,\"child_errno\":%d,\"cleanup_errno\":%d,\"spawned\":%d,\"reaped\":%d,\"exit_code\":%d,\"signal\":%d,\"prepared\":%s,\"guest_uid\":%d,\"guest_gid\":%d,\"capabilities_zero\":%s,\"no_new_privs\":%d,\"filter_verified\":%d,\"namespaces_private\":%s,\"metadata_received\":%s,\"parent_unchanged\":%s,\"loops_released\":%s,\"temporary_directory_removed\":%s,\"output\":",r.error,r.child.error,r.cleanup_error,r.spawned,r.reaped,r.exit_code,r.signal,r.child.prepared?"true":"false",r.child.uid,r.child.gid,r.child.caps_zero?"true":"false",r.child.nnp,r.child.filter_verified,r.child.namespaces_private?"true":"false",r.metadata_received?"true":"false",r.parent_unchanged?"true":"false",r.loops_released?"true":"false",r.temp_removed?"true":"false");json_string(r.output);
    printf(",\"loop_control_errno\":%d,\"loop_node_errno\":%d,\"loop_candidates\":%d",r.child.loop_control_errno,r.child.loop_node_errno,r.child.loop_candidates);
    fputs(",\"scope\":\"Pinned upstream EvoX linker/mksh only, capless UID65534, default-deny seccomp, private mounts/network, no host data/proc/dev bind, no HAL or Android framework. Recovery by reboot is acceptable; no host takeover attempted.\"}\n",stdout);return rc;
}
int main(int argc,char **argv){
    if(argc==3&&!strcmp(argv[1],"--preview-gsi"))return pv_main(argv[2]);
    if(argc==3&&!strcmp(argv[1],"--verify-image")){int fd=open(argv[2],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 40;char sha[65]={0};int error=pv_exact_file(fd,PV_IMAGE_BYTES,PV_IMAGE_SHA,sha);if(!error)error=pv_ext4(fd,0);close(fd);printf("image_sha256=%s\nerrno=%d\n",sha,error);return error?40:0;}
    return pd_diagnostic_main(argc,argv);
}
