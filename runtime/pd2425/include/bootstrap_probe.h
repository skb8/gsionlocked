/* Trusted inert PID/proc/rootfs scaffold, NOT Android init or an untrusted sandbox. */
#ifndef PD2425_BOOTSTRAP_PROBE_H
#define PD2425_BOOTSTRAP_PROBE_H
#include <limits.h>
#include <sys/statvfs.h>
struct pd_boot_child {
    int index,error,pid,ppid,proc_self_pid,proc_pid_count,root_read_only,proc_read_only,fds_closed;
    uint64_t pid_dev,pid_ino,mnt_dev,mnt_ino,root_dev,root_ino;char stage[48];
};
struct pd_boot_context {
    struct pd_namespace_context ns;
    struct stat parent_pid,parent_root;
    struct pd_boot_child children[2];int received[2];
};
_Static_assert(offsetof(struct pd_boot_context,ns)==0,"namespace/cgroup context must be first");
_Static_assert(sizeof(struct pd_boot_child)<=512,"bootstrap report must be atomic");
static int pd_close_except(int keep) {
#ifdef SYS_close_range
    if(keep<0){errno=EINVAL;return -1;}
    if(keep>0&&syscall(SYS_close_range,0U,(unsigned)keep-1,0U))return -1;
    return (int)syscall(SYS_close_range,(unsigned)keep+1,UINT_MAX,0U);
#else
    (void)keep;errno=ENOSYS;return -1;
#endif
}
static void pd_boot_worker(struct pd_boot_context *ctx,int index,struct pd_boot_child *r) {
    memset(r,0,sizeof(*r));r->index=index;strcpy(r->stage,"pid_namespace");
    if(index<0||index>1){r->error=EINVAL;return;}
    r->pid=getpid();r->ppid=getppid();
    if(r->pid!=1||r->ppid!=0){r->error=EPROTO;return;}
    struct stat pid_ns,mnt,root;struct statfs fs;
#define PD_BOOT_STEP(label,call) do{strcpy(r->stage,label);if((call)<0){r->error=errno?errno:EIO;goto done;}}while(0)
    /* PID1 already exists; proc must be mounted by this process, never host proc. */
    PD_BOOT_STEP("mount_namespace",unshare(CLONE_NEWNS));
    PD_BOOT_STEP("mounts_private",mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL));
    PD_BOOT_STEP("pid_namespace_stat",stat("/proc/self/ns/pid",&pid_ns));
    PD_BOOT_STEP("mount_namespace_stat",stat("/proc/self/ns/mnt",&mnt));
    r->pid_dev=pid_ns.st_dev;r->pid_ino=pid_ns.st_ino;r->mnt_dev=mnt.st_dev;r->mnt_ino=mnt.st_ino;
    if(!pid_ns.st_ino||!mnt.st_ino||pd_same_inode(&pid_ns,&ctx->parent_pid)||pd_same_inode(&mnt,&ctx->ns.parent_mnt)){r->error=EXDEV;goto done;}
    const char *target=ctx->ns.targets[index];char proc[192];snprintf(proc,sizeof(proc),"%s/proc",target);
    PD_BOOT_STEP("rootfs_tmpfs",mount("tmpfs",target,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=1m,mode=0700"));
    PD_BOOT_STEP("proc_directory",mkdir(proc,0700));
    PD_BOOT_STEP("private_proc_mount",mount("proc",proc,"proc",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL));
    PD_BOOT_STEP("rootfs_readonly",mount(NULL,target,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL));
    /* Do not carry host directory/device/ns FDs across chroot. Only the
       write-only result pipe survives. No code from a GSI is executed. */
    PD_BOOT_STEP("close_inherited_fds",pd_close_except(ctx->ns.report_fd[1]));r->fds_closed=1;
    PD_BOOT_STEP("chroot",chroot(target));
    PD_BOOT_STEP("root_cwd",chdir("/"));
    PD_BOOT_STEP("root_stat",stat("/",&root));
    r->root_dev=root.st_dev;r->root_ino=root.st_ino;
    if(!root.st_ino||root.st_dev==ctx->parent_root.st_dev){r->error=EXDEV;goto done;}
    PD_BOOT_STEP("root_filesystem",statfs("/",&fs));
    if((unsigned long)fs.f_type!=TMPFS_MAGIC||!(fs.f_flags&ST_RDONLY)){r->error=EPROTO;goto done;}r->root_read_only=1;
    PD_BOOT_STEP("proc_filesystem",statfs("/proc",&fs));
    if((unsigned long)fs.f_type!=PROC_SUPER_MAGIC||!(fs.f_flags&ST_RDONLY)){r->error=EPROTO;goto done;}r->proc_read_only=1;
    char self[32]={0};ssize_t count;
    PD_BOOT_STEP("proc_self",count=readlink("/proc/self",self,sizeof(self)-1));
    if(count!=1||self[0]!='1'){r->error=EPROTO;goto done;}r->proc_self_pid=1;
    /* A newly mounted proc must show exactly this inert PID 1, no host tasks. */
    strcpy(r->stage,"proc_members");DIR *directory=opendir("/proc");if(!directory){r->error=errno;goto done;}
    struct dirent *entry;int scan_error=0;
    for(;;){errno=0;entry=readdir(directory);if(!entry){scan_error=errno;break;}
        const char *name=entry->d_name;if(!*name)continue;int digits=1;
        for(const char *p=name;*p;p++)if(*p<'0'||*p>'9')digits=0;
        if(digits){r->proc_pid_count++;if(strcmp(name,"1"))scan_error=EXDEV;}
        if(scan_error)break;
    }
    closedir(directory);if(scan_error||r->proc_pid_count!=1){r->error=scan_error?scan_error:EPROTO;goto done;}
    /* Empty scaffold: host filesystem contents must not leak through chroot. */
    const char *absent[]={"/system","/vendor","/data","/sys","/dev"};
    for(unsigned n=0;n<sizeof(absent)/sizeof(absent[0]);n++){
        struct stat info;strcpy(r->stage,"host_paths_absent");
        if(!lstat(absent[n],&info)||errno!=ENOENT){r->error=EXDEV;goto done;}
    }
    strcpy(r->stage,"complete");
done:
#undef PD_BOOT_STEP
    return;
}
static int pd_boot_create(void *opaque) {
    struct pd_boot_context *ctx=opaque;
    if(stat("/proc/self/ns/pid",&ctx->parent_pid)||stat("/",&ctx->parent_root))return errno;
    if(!ctx->parent_pid.st_ino||!ctx->parent_root.st_ino)return ENODEV;
    return pd_namespace_create(&ctx->ns);
}
static void pd_boot_child_task(void *opaque,int index) {
    struct pd_boot_context *ctx=opaque;close(ctx->ns.report_fd[0]);struct pd_boot_child result;
    pd_boot_worker(ctx,index,&result);ssize_t n;
    do{n=write(ctx->ns.report_fd[1],&result,sizeof(result));}while(n<0&&errno==EINTR);
    (void)n;close(ctx->ns.report_fd[1]); // PID 1 then waits for guardian's cgroup.kill.
}
static int pd_boot_results_valid(const struct pd_boot_context *ctx) {
    for(int n=0;n<2;n++){
        const struct pd_boot_child *r=&ctx->children[n];
        if(!ctx->received[n])return ENODATA;
        if(r->error)return r->error;
        if(strcmp(r->stage,"complete")||r->pid!=1||r->ppid!=0||r->proc_self_pid!=1||r->proc_pid_count!=1||!r->root_read_only||!r->proc_read_only||!r->fds_closed||!r->pid_ino||!r->mnt_ino||!r->root_ino)return EPROTO;
        if((r->pid_dev==(uint64_t)ctx->parent_pid.st_dev&&r->pid_ino==(uint64_t)ctx->parent_pid.st_ino)||(r->mnt_dev==(uint64_t)ctx->ns.parent_mnt.st_dev&&r->mnt_ino==(uint64_t)ctx->ns.parent_mnt.st_ino)||r->root_dev==(uint64_t)ctx->parent_root.st_dev)return EXDEV;
    }
    const struct pd_boot_child *a=&ctx->children[0],*b=&ctx->children[1];
    if((a->pid_dev==b->pid_dev&&a->pid_ino==b->pid_ino)||(a->mnt_dev==b->mnt_dev&&a->mnt_ino==b->mnt_ino)||a->root_dev==b->root_dev)return EXDEV;
    return 0;
}
static int pd_boot_inspect(void *opaque,const pid_t *children) {
    (void)children;struct pd_boot_context *ctx=opaque;close(ctx->ns.report_fd[1]);ctx->ns.report_fd[1]=-1;
    for(int n=0;n<2;n++){
        struct pollfd ready={.fd=ctx->ns.report_fd[0],.events=POLLIN};int rc;
        do{rc=poll(&ready,1,4000);}while(rc<0&&errno==EINTR);
        if(rc<0)return errno;
        if(!rc)return ETIMEDOUT;
        if(!(ready.revents&POLLIN))return EPIPE;
        struct pd_boot_child r;ssize_t count;do{count=read(ctx->ns.report_fd[0],&r,sizeof(r));}while(count<0&&errno==EINTR);
        if(count!=(ssize_t)sizeof(r)||r.index<0||r.index>1||ctx->received[r.index])return EPROTO;
        r.stage[sizeof(r.stage)-1]=0;ctx->children[r.index]=r;ctx->received[r.index]=1;
    }
    int error=pd_boot_results_valid(ctx),parent_error=pd_namespace_parent_check(&ctx->ns);struct stat now;
    if(!parent_error&&(stat("/proc/self/ns/pid",&now)||!pd_same_inode(&now,&ctx->parent_pid)||stat("/",&now)||!pd_same_inode(&now,&ctx->parent_root)))parent_error=EXDEV;
    if(parent_error)ctx->ns.parent_unchanged=0;
    return parent_error?parent_error:error;
}
static int pd_boot_selftest_json(int matched,const char *fingerprint) {
    struct pd_boot_context ctx={.ns={.group={.root_fd=-1,.group_fd=-1},.report_fd={-1,-1},.temp_fd=-1}};
    struct pd_cgroup_ops ops={.create=pd_boot_create,.add=pd_cg_add,.members=pd_cg_members,.populated=pd_cg_populated,.kill_group=pd_cg_kill,.remove_group=pd_namespace_remove,.context=&ctx,.child_task=pd_boot_child_task,.inspect_children=pd_boot_inspect,.new_pid_namespace=1};
    struct pd_cgroup_result result={.stage="identity"};int rc=40;
    if(!matched){result.error=EINVAL;rc=31;}
    else if(getuid()!=0){result.stage="uid";result.error=EPERM;}
    else {char enforce[16];int error=read_text("/sys/fs/selinux/enforce",enforce,sizeof(enforce));
        if(error||(strcmp(enforce,"1")&&strcmp(enforce,"1\n"))){result.stage="selinux_enforce";result.error=error?error:EPERM;}
        else rc=pd_guarded_cgroup_run(&ops,&result,25);
    }
    if(!rc&&(!ctx.ns.parent_unchanged||!ctx.ns.temp_removed)){result.error=EPROTO;rc=40;}
    fputs("{\"schema\":1,\"component\":\"bootstrap-self-test\",\"runtime_ready\":false,\"test_only_children\":true,\"host_services_changed\":false,\"fingerprint\":",stdout);json_string(fingerprint);
    fputs(",\"boot_id\":",stdout);json_file("/proc/sys/kernel/random/boot_id");
    printf(",\"uid\":%lu,\"passed\":%s,\"parent_checked\":%s,\"parent_unchanged\":%s,\"temporary_directory_removed\":%s,\"group_created\":%s,\"is_cgroup2\":%s,\"spawned\":%d,\"pidfds\":%d,\"membership_verified\":%s,\"kill_succeeded\":%s,\"drained\":%s,\"reaped\":%d,\"errno\":%d,\"cleanup_errno\":%d,\"cleanup_complete\":%s,\"stage\":",(unsigned long)getuid(),rc?"false":"true",ctx.ns.parent_checked?"true":"false",ctx.ns.parent_unchanged?"true":"false",ctx.ns.temp_removed?"true":"false",ctx.ns.group.ever_created?"true":"false",ctx.ns.group.is_cgroup2?"true":"false",result.spawned,result.pidfds,result.membership_verified?"true":"false",result.kill_succeeded?"true":"false",result.drained?"true":"false",result.reaped,result.error,result.cleanup_errno,!result.cleanup_errno&&result.reaped==result.spawned&&ctx.ns.temp_removed?"true":"false");json_string(result.stage);
    printf(",\"parent_pid_namespace\":{\"device\":%llu,\"inode\":%llu},\"parent_mount_namespace\":{\"device\":%llu,\"inode\":%llu},\"parent_root\":{\"device\":%llu,\"inode\":%llu},\"children\":[",(unsigned long long)ctx.parent_pid.st_dev,(unsigned long long)ctx.parent_pid.st_ino,(unsigned long long)ctx.ns.parent_mnt.st_dev,(unsigned long long)ctx.ns.parent_mnt.st_ino,(unsigned long long)ctx.parent_root.st_dev,(unsigned long long)ctx.parent_root.st_ino);
    for(int n=0;n<2;n++){
        const struct pd_boot_child *r=&ctx.children[n];if(n)putchar(',');
        printf("{\"index\":%d,\"reported\":%s,\"errno\":%d,\"pid\":%d,\"ppid\":%d,\"proc_self_pid\":%d,\"proc_pid_count\":%d,\"root_read_only\":%s,\"proc_read_only\":%s,\"inherited_fds_closed\":%s,\"pid_namespace\":{\"device\":%llu,\"inode\":%llu},\"mount_namespace\":{\"device\":%llu,\"inode\":%llu},\"root\":{\"device\":%llu,\"inode\":%llu},\"stage\":",n,ctx.received[n]?"true":"false",r->error,r->pid,r->ppid,r->proc_self_pid,r->proc_pid_count,r->root_read_only?"true":"false",r->proc_read_only?"true":"false",r->fds_closed?"true":"false",(unsigned long long)r->pid_dev,(unsigned long long)r->pid_ino,(unsigned long long)r->mnt_dev,(unsigned long long)r->mnt_ino,(unsigned long long)r->root_dev,(unsigned long long)r->root_ino);json_string(r->stage);putchar('}');
    }
    puts("],\"scope\":\"Trusted inert PID1/proc/read-only tmpfs scaffold only. No Android init, GSI execution, untrusted sandbox, BPF/SELinux policy or hardware handoff.\"}");return rc;
}
#endif
