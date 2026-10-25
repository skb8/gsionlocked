/* Trusted, root-only namespace/BinderFS probe. No GSI/rootfs/PID isolation claim. */
#ifndef PD2425_NAMESPACE_PROBE_H
#define PD2425_NAMESPACE_PROBE_H
#include <sched.h>
#include <stddef.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <linux/android/binder.h>
#include <linux/android/binderfs.h>

static const char *const pd_binder_names[]={"binder","hwbinder","vndbinder"};
struct pd_namespace_child {
    int index,error,private_mounts,private_network,devices_created,protocol[3];
    uint64_t mnt_dev,mnt_ino,net_dev,net_ino;unsigned majors[3],minors[3];char stage[48];
};
struct pd_namespace_context {
    struct pd_cgroup_fs group; /* First member: cgroup callbacks receive this object. */
    int report_fd[2],temp_fd,temp_created,dirs_created[2],temp_removed,parent_checked,parent_unchanged;
    char temp_path[128],targets[2][160];struct stat parent_mnt,parent_net,host_binders[3],targets_before[2];int host_present[3];
    struct pd_namespace_child children[2];int received[2];
};
_Static_assert(offsetof(struct pd_namespace_context,group)==0,"cgroup context must be first");
_Static_assert(sizeof(struct pd_namespace_child)<=512,"child report must fit one atomic pipe write");
static int pd_same_inode(const struct stat *a,const struct stat *b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino;}
static void pd_namespace_worker(struct pd_namespace_context *ctx,int index,struct pd_namespace_child *result) {
    memset(result,0,sizeof(*result));result->index=index;strcpy(result->stage,"index");
    if(index<0||index>1){result->error=EINVAL;return;}
    int control=-1,device_fd=-1;struct stat mnt,net;
#define PD_NS_STEP(label,call) do {strcpy(result->stage,label);if((call)<0){result->error=errno?errno:EIO;goto done;}} while(0)
    PD_NS_STEP("unshare",unshare(CLONE_NEWNS|CLONE_NEWNET));
    PD_NS_STEP("mounts_private",mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL));
    PD_NS_STEP("mount_namespace",stat("/proc/self/ns/mnt",&mnt));
    PD_NS_STEP("network_namespace",stat("/proc/self/ns/net",&net));
    result->mnt_dev=(uint64_t)mnt.st_dev;result->mnt_ino=(uint64_t)mnt.st_ino;
    result->net_dev=(uint64_t)net.st_dev;result->net_ino=(uint64_t)net.st_ino;
    if(!mnt.st_ino||!net.st_ino||pd_same_inode(&mnt,&ctx->parent_mnt)||pd_same_inode(&net,&ctx->parent_net)){result->error=EXDEV;goto done;}
    result->private_mounts=result->private_network=1;
    PD_NS_STEP("private_tmpfs",mount("tmpfs",ctx->targets[index],"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=1m,mode=0700"));
    char binder_dir[192],path[224];snprintf(binder_dir,sizeof(binder_dir),"%s/binderfs",ctx->targets[index]);
    PD_NS_STEP("binder_directory",mkdir(binder_dir,0700));
    PD_NS_STEP("binderfs_mount",mount("binder",binder_dir,"binder",MS_NOSUID|MS_NOEXEC,"max=4"));
    snprintf(path,sizeof(path),"%s/binder-control",binder_dir);
    PD_NS_STEP("binder_control",control=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW));
    for(int n=0;n<3;n++) {
        struct binderfs_device device={0};strcpy(device.name,pd_binder_names[n]);
        PD_NS_STEP("binder_add",ioctl(control,BINDER_CTL_ADD,&device));
        snprintf(path,sizeof(path),"%s/%s",binder_dir,pd_binder_names[n]);struct stat info;
        PD_NS_STEP("binder_node",stat(path,&info));
        if(!S_ISCHR(info.st_mode)||info.st_rdev!=makedev(device.major,device.minor)){result->error=EPROTO;goto done;}
        for(int k=0;k<3;k++)if(ctx->host_present[k]&&info.st_rdev==ctx->host_binders[k].st_rdev){result->error=EXDEV;goto done;}
        for(int k=0;k<n;k++)if(device.major==result->majors[k]&&device.minor==result->minors[k]){result->error=EADDRINUSE;goto done;}
        result->majors[n]=device.major;result->minors[n]=device.minor;
        PD_NS_STEP("binder_open",device_fd=open(path,O_RDWR|O_CLOEXEC|O_NOFOLLOW));
        struct binder_version version={0};PD_NS_STEP("binder_version",ioctl(device_fd,BINDER_VERSION,&version));
        close(device_fd);device_fd=-1;result->protocol[n]=version.protocol_version;
        if(version.protocol_version!=BINDER_CURRENT_PROTOCOL_VERSION){result->error=EPROTO;goto done;}
        result->devices_created++;
    }
    strcpy(result->stage,"complete");
done:
    if(device_fd>=0)close(device_fd);
    if(control>=0)close(control);
#undef PD_NS_STEP
}
static int pd_namespace_create(void *opaque) {
    struct pd_namespace_context *ctx=opaque;
    if(stat("/proc/self/ns/mnt",&ctx->parent_mnt)||stat("/proc/self/ns/net",&ctx->parent_net))return errno;
    if(!ctx->parent_mnt.st_ino||!ctx->parent_net.st_ino)return ENODEV;
    for(int n=0;n<3;n++) {
        char path[32];snprintf(path,sizeof(path),"/dev/%s",pd_binder_names[n]);
        if(!stat(path,&ctx->host_binders[n])){
            if(!S_ISCHR(ctx->host_binders[n].st_mode))return ENODEV;
            ctx->host_present[n]=1;
        }else if(errno!=ENOENT)return errno;
    }
    if(!ctx->host_present[0])return ENODEV; // Do not claim independence without seeing stock Binder.
    int error=pd_cg_create(&ctx->group);if(error)return error;
    strcpy(ctx->temp_path,"/data/local/tmp/gsionlocked_ns_XXXXXX");
    if(!mkdtemp(ctx->temp_path))return errno;
    ctx->temp_created=1;
    ctx->temp_fd=open(ctx->temp_path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(ctx->temp_fd<0)return errno;
    const char *names[]={"one","two"};
    for(int n=0;n<2;n++) {
        if(mkdirat(ctx->temp_fd,names[n],0700))return errno;
        ctx->dirs_created[n]=1;snprintf(ctx->targets[n],sizeof(ctx->targets[n]),"%s/%s",ctx->temp_path,names[n]);
        if(fstatat(ctx->temp_fd,names[n],&ctx->targets_before[n],AT_SYMLINK_NOFOLLOW))return errno;
    }
    if(pipe2(ctx->report_fd,O_CLOEXEC))return errno;
    return 0;
}
static void pd_namespace_child_task(void *opaque,int index) {
    struct pd_namespace_context *ctx=opaque;close(ctx->report_fd[0]);
    struct pd_namespace_child result;pd_namespace_worker(ctx,index,&result);
    /* One atomic record, comfortably smaller than PIPE_BUF. Remain alive for cgroup.kill. */
    ssize_t n;do{n=write(ctx->report_fd[1],&result,sizeof(result));}while(n<0&&errno==EINTR);
    (void)n;close(ctx->report_fd[1]);
}
static int pd_namespace_parent_check(struct pd_namespace_context *ctx) {
    struct stat now;ctx->parent_checked=1;
    if(stat("/proc/self/ns/mnt",&now)||!pd_same_inode(&now,&ctx->parent_mnt))return EXDEV;
    if(stat("/proc/self/ns/net",&now)||!pd_same_inode(&now,&ctx->parent_net))return EXDEV;
    for(int n=0;n<3;n++) {
        char path[32];snprintf(path,sizeof(path),"/dev/%s",pd_binder_names[n]);
        int rc=stat(path,&now);
        if(ctx->host_present[n]){if(rc||!pd_same_inode(&now,&ctx->host_binders[n])||now.st_rdev!=ctx->host_binders[n].st_rdev)return ESTALE;}
        else if(!rc||errno!=ENOENT)return ESTALE;
    }
    for(int n=0;n<2;n++){
        if(stat(ctx->targets[n],&now)||!pd_same_inode(&now,&ctx->targets_before[n]))return EXDEV;
        char path[192];snprintf(path,sizeof(path),"%s/binderfs",ctx->targets[n]);
        if(!lstat(path,&now)||errno!=ENOENT)return EXDEV;
    }
    ctx->parent_unchanged=1;return 0;
}
static int pd_namespace_results_valid(const struct pd_namespace_context *ctx) {
    const struct pd_namespace_child *a=&ctx->children[0],*b=&ctx->children[1];
    if(!ctx->received[0]||!ctx->received[1])return ENODATA;
    for(int n=0;n<2;n++){
        const struct pd_namespace_child *r=&ctx->children[n];
        if(r->error)return r->error;
        if(r->devices_created!=3||!r->private_mounts||!r->private_network||!r->mnt_ino||!r->net_ino)return EPROTO;
        if((r->mnt_dev==(uint64_t)ctx->parent_mnt.st_dev&&r->mnt_ino==(uint64_t)ctx->parent_mnt.st_ino)||(r->net_dev==(uint64_t)ctx->parent_net.st_dev&&r->net_ino==(uint64_t)ctx->parent_net.st_ino))return EXDEV;
        for(int k=0;k<3;k++){
            if(r->protocol[k]!=BINDER_CURRENT_PROTOCOL_VERSION||!r->majors[k])return EPROTO;
            for(int j=0;j<k;j++)if(r->majors[k]==r->majors[j]&&r->minors[k]==r->minors[j])return EADDRINUSE;
            for(int j=0;j<3;j++)if(ctx->host_present[j]&&makedev(r->majors[k],r->minors[k])==ctx->host_binders[j].st_rdev)return EXDEV;
        }
    }
    if((a->mnt_dev==b->mnt_dev&&a->mnt_ino==b->mnt_ino)||(a->net_dev==b->net_dev&&a->net_ino==b->net_ino))return EXDEV;
    for(int i=0;i<3;i++)for(int j=0;j<3;j++)if(a->majors[i]==b->majors[j]&&a->minors[i]==b->minors[j])return EADDRINUSE;
    return 0;
}
static int pd_namespace_inspect(void *opaque,const pid_t *children) {
    (void)children;struct pd_namespace_context *ctx=opaque;
    close(ctx->report_fd[1]);ctx->report_fd[1]=-1;
    for(int n=0;n<2;n++) {
        struct pollfd ready={.fd=ctx->report_fd[0],.events=POLLIN};int rc;
        do{rc=poll(&ready,1,3000);}while(rc<0&&errno==EINTR);
        if(rc<0)return errno;
        if(!rc)return ETIMEDOUT;
        if(!(ready.revents&POLLIN))return EPIPE;
        struct pd_namespace_child result;ssize_t size;
        do{size=read(ctx->report_fd[0],&result,sizeof(result));}while(size<0&&errno==EINTR);
        if(size!=(ssize_t)sizeof(result))return EPROTO;
        if(result.index<0||result.index>1||ctx->received[result.index])return EPROTO;
        result.stage[sizeof(result.stage)-1]=0;ctx->children[result.index]=result;ctx->received[result.index]=1;
    }
    int error=pd_namespace_results_valid(ctx);if(error)return error;
    return pd_namespace_parent_check(ctx);
}
static int pd_namespace_remove(void *opaque) {
    struct pd_namespace_context *ctx=opaque;int error=pd_cg_remove(&ctx->group);
    for(int n=0;n<2;n++)if(ctx->report_fd[n]>=0){close(ctx->report_fd[n]);ctx->report_fd[n]=-1;}
    const char *names[]={"one","two"};int temp_error=0;
    for(int n=0;n<2;n++)if(ctx->dirs_created[n]&&unlinkat(ctx->temp_fd,names[n],AT_REMOVEDIR))temp_error=errno;
    if(ctx->temp_fd>=0){close(ctx->temp_fd);ctx->temp_fd=-1;}
    if(ctx->temp_created&&rmdir(ctx->temp_path))temp_error=errno;
    ctx->temp_removed=!temp_error;
    return error?error:temp_error;
}
static int pd_namespace_selftest_json(int matched,const char *fingerprint) {
    struct pd_namespace_context ctx={.group={.root_fd=-1,.group_fd=-1},.report_fd={-1,-1},.temp_fd=-1};
    struct pd_cgroup_ops ops={.create=pd_namespace_create,.add=pd_cg_add,.members=pd_cg_members,.populated=pd_cg_populated,.kill_group=pd_cg_kill,.remove_group=pd_namespace_remove,.context=&ctx,.child_task=pd_namespace_child_task,.inspect_children=pd_namespace_inspect};
    struct pd_cgroup_result result={.stage="identity"};int rc=40;
    if(!matched){result.error=EINVAL;rc=31;}
    else if(getuid()!=0){result.stage="uid";result.error=EPERM;}
    else {
        char enforce[16];int error=read_text("/sys/fs/selinux/enforce",enforce,sizeof(enforce));
        if(error||(strcmp(enforce,"1")&&strcmp(enforce,"1\n"))){result.stage="selinux_enforce";result.error=error?error:EPERM;}
        else rc=pd_guarded_cgroup_run(&ops,&result,20);
    }
    if(!rc&&(!ctx.parent_unchanged||!ctx.temp_removed)){result.error=EPROTO;rc=40;}
    fputs("{\"schema\":1,\"component\":\"namespace-self-test\",\"runtime_ready\":false,\"test_only_children\":true,\"host_services_changed\":false,\"fingerprint\":",stdout);json_string(fingerprint);
    fputs(",\"boot_id\":",stdout);json_file("/proc/sys/kernel/random/boot_id");
    printf(",\"uid\":%lu,\"passed\":%s,\"parent_unchanged\":%s,\"temporary_directory_removed\":%s,\"spawned\":%d,\"pidfds\":%d,\"membership_verified\":%s,\"kill_succeeded\":%s,\"drained\":%s,\"reaped\":%d,\"stage\":",(unsigned long)getuid(),rc==0?"true":"false",ctx.parent_unchanged?"true":"false",ctx.temp_removed?"true":"false",result.spawned,result.pidfds,result.membership_verified?"true":"false",result.kill_succeeded?"true":"false",result.drained?"true":"false",result.reaped);
    json_string(result.stage);
    printf(",\"group_created\":%s,\"is_cgroup2\":%s,\"parent_checked\":%s,\"parent_mount_namespace\":{\"device\":%llu,\"inode\":%llu},\"parent_network_namespace\":{\"device\":%llu,\"inode\":%llu}",ctx.group.ever_created?"true":"false",ctx.group.is_cgroup2?"true":"false",ctx.parent_checked?"true":"false",(unsigned long long)ctx.parent_mnt.st_dev,(unsigned long long)ctx.parent_mnt.st_ino,(unsigned long long)ctx.parent_net.st_dev,(unsigned long long)ctx.parent_net.st_ino);
    fputs(",\"parent_binder\":[",stdout);
    for(int n=0;n<3;n++){if(n)putchar(',');fputs("{\"name\":",stdout);json_string(pd_binder_names[n]);printf(",\"present\":%s,\"major\":%u,\"minor\":%u}",ctx.host_present[n]?"true":"false",ctx.host_present[n]?(unsigned)major(ctx.host_binders[n].st_rdev):0U,ctx.host_present[n]?(unsigned)minor(ctx.host_binders[n].st_rdev):0U);}putchar(']');
    printf(",\"errno\":%d,\"cleanup_errno\":%d,\"cleanup_complete\":%s,\"children\":[",result.error,result.cleanup_errno,!result.cleanup_errno&&result.reaped==result.spawned&&ctx.temp_removed?"true":"false");
    for(int n=0;n<2;n++){
        if(n)putchar(',');
        const struct pd_namespace_child *r=&ctx.children[n];printf("{\"index\":%d,\"reported\":%s,\"errno\":%d,\"stage\":",n,ctx.received[n]?"true":"false",r->error);json_string(r->stage);
        printf(",\"mount_namespace\":{\"device\":%llu,\"inode\":%llu},\"network_namespace\":{\"device\":%llu,\"inode\":%llu},\"private_mounts\":%s,\"private_network\":%s,\"devices_created\":%d,\"binder\":[",(unsigned long long)r->mnt_dev,(unsigned long long)r->mnt_ino,(unsigned long long)r->net_dev,(unsigned long long)r->net_ino,r->private_mounts?"true":"false",r->private_network?"true":"false",r->devices_created);
        for(int k=0;k<3;k++){if(k)putchar(',');fputs("{\"name\":",stdout);json_string(pd_binder_names[k]);printf(",\"major\":%u,\"minor\":%u,\"protocol\":%d}",r->majors[k],r->minors[k],r->protocol[k]);}fputs("]}",stdout);
    }
    puts("],\"scope\":\"Root-only mount/network/BinderFS. No GSI, rootfs/PID/BPF/SELinux isolation or hardware handoff validated. No stock Binder transaction or service registration.\"}");return rc;
}
#endif
