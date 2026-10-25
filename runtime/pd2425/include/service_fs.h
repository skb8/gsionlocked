/* Owned-child service environment. No host /proc, /dev or writable policy view. */
#ifndef PD2425_SERVICE_FS_H
#define PD2425_SERVICE_FS_H
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <linux/android/binder.h>
#include <linux/android/binderfs.h>
#include "service_entry.h"
#define SM_SELINUX_MAGIC 0xf97cff8cU
static const char *sm_fs_stages[]={"none","stock_binder_metadata","private_dev","binderfs_mount","private_binder_nodes","selinux_source","selinux_view","own_proc_attr","packaged_helper","complete","service_entry"};
struct sm_environment {int stage;int binder_verified,selinux_verified,self_proc_only,helper_verified,context_verified,entry_verified;uint64_t binder_dev,binder_ino,binder_rdev,service_dev,service_ino,linker_dev,linker_ino,host_dev[3],host_ino[3],host_rdev[3];int host_present[3];};
static int sm_directory(int root,const char *name){struct open_how h={.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC,.resolve=RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS};return (int)syscall(SYS_openat2,root,name,&h,sizeof(h));}
static void sm_fdpath(char *out,size_t size,int fd){snprintf(out,size,"/proc/self/fd/%d",fd);}
static int sm_label_directory(int fd){const char label[]="u:object_r:system_file:s0";return fsetxattr(fd,"security.selinux",label,sizeof(label),0);}
static int sm_new_tmpfs(int root,const char *name,const char *options,unsigned long extra){
    int fd=sm_directory(root,name);if(fd<0)return -1;char path[64];sm_fdpath(path,sizeof(path),fd);
    int result=mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV|extra,options),error=errno;close(fd);if(result){errno=error;return -1;}int reopened=sm_directory(root,name);if(reopened>=0&&sm_label_directory(reopened)){int e=errno;close(reopened);errno=e;return -1;}return reopened;
}
static int sm_readonly(int fd,unsigned long extra){char path[64];sm_fdpath(path,sizeof(path),fd);if(mount(NULL,path,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|extra,NULL))return -1;struct statvfs fs;if(fstatvfs(fd,&fs))return -1;if(!(fs.f_flag&ST_RDONLY)){errno=EPROTO;return -1;}return 0;}
static int sm_bind_file(int source,int parent,const char *name,int readonly,unsigned expected_magic){
    int target=openat(parent,name,O_PATH|O_CLOEXEC|O_NOFOLLOW);if(target<0)return -1;
    char from[64],to[64];sm_fdpath(from,sizeof(from),source);sm_fdpath(to,sizeof(to),target);
    int result=mount(from,to,NULL,MS_BIND,NULL),error=errno;close(target);if(result){errno=error;return -1;}
    target=openat(parent,name,O_PATH|O_CLOEXEC|O_NOFOLLOW);if(target<0)return -1;
    struct stat a,b;struct statfs fs;struct statvfs flags;error=0;
    if(fstat(source,&a)||fstat(target,&b)||fstatfs(target,&fs)||fstatvfs(target,&flags))error=errno;
    else if(!S_ISREG(b.st_mode)||!pd_same_inode(&a,&b)||(uint32_t)fs.f_type!=expected_magic)error=EXDEV;
    if(!error&&readonly&&sm_readonly(target,MS_NOEXEC))error=errno;
    if(!error&&!readonly&&(flags.f_flag&ST_RDONLY))error=EROFS;
    close(target);if(error){errno=error;return -1;}return 0;
}
static int sm_make_path(int parent,const char *name,mode_t mode){if(mkdirat(parent,name,mode))return -1;int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd>=0&&sm_label_directory(fd)){int error=errno;close(fd);errno=error;return -1;}return fd;}
static int sm_prepare_fs(int root,int helper,uint64_t helper_bytes,const char *helper_sha,struct sm_environment *result,int *context_fd){
    int dev=-1,bfs=-1,control=-1,fd=-1,sys=-1,fsdir=-1,sel=-1,host_sel=-1,query[2]={-1,-1},proc=-1,self=-1,attr=-1,host_attr=-1,host_exec=-1,service=-1,bin=-1,data=-1,local=-1,tmp=-1,error=0;char path[96],digest[65];struct stat stock[3];int present[3]={0};
    const char *names[]={"binder","hwbinder","vndbinder"},*queries[]={"access","context"};
#define SM_TRY(call) do{if((call)<0){error=errno?errno:EIO;goto done;}}while(0)
    result->stage=1;
    for(int n=0;n<3;n++){snprintf(path,sizeof(path),"/dev/%s",names[n]);if(!stat(path,&stock[n])){if(!S_ISCHR(stock[n].st_mode)){error=ENODEV;goto done;}present[n]=1;result->host_present[n]=1;result->host_dev[n]=stock[n].st_dev;result->host_ino[n]=stock[n].st_ino;result->host_rdev[n]=stock[n].st_rdev;}else if(errno!=ENOENT){error=errno;goto done;}}
    if(!present[0]){error=ENODEV;goto done;}
    char binder_label[256]={0};ssize_t label_bytes=getxattr("/dev/binder","security.selinux",binder_label,sizeof(binder_label)-1);
    if(label_bytes<=0){error=errno?errno:ENODATA;goto done;}
    for(ssize_t n=0;n<label_bytes;n++)if(binder_label[n]&&!(binder_label[n]==':'||binder_label[n]=='_'||binder_label[n]==','||binder_label[n]=='.'||binder_label[n]=='-'||(binder_label[n]>='a'&&binder_label[n]<='z')||(binder_label[n]>='A'&&binder_label[n]<='Z')||(binder_label[n]>='0'&&binder_label[n]<='9'))){error=EINVAL;goto done;}
    struct stat current_binder;SM_TRY(stat("/dev/binder",&current_binder));if(!pd_same_inode(&current_binder,&stock[0])||current_binder.st_rdev!=stock[0].st_rdev){error=ESTALE;goto done;}
    char binder_options[512];snprintf(binder_options,sizeof(binder_options),"max=4,context=\"%s\",rootcontext=\"u:object_r:system_file:s0\",fscontext=\"u:object_r:tmpfs:s0\"",binder_label);
    result->stage=2;
    SM_TRY(dev=sm_new_tmpfs(root,"dev","size=1m,mode=0755",MS_NOEXEC));SM_TRY(bfs=sm_make_path(dev,"binderfs",0755));sm_fdpath(path,sizeof(path),bfs);result->stage=3;SM_TRY(mount("binder",path,"binder",MS_NOSUID|MS_NOEXEC,binder_options));close(bfs);bfs=-1;
    SM_TRY(bfs=openat(dev,"binderfs",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));SM_TRY(control=openat(bfs,"binder-control",O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
    struct stat ci;struct statfs btype;SM_TRY(fstat(control,&ci));SM_TRY(fstatfs(control,&btype));SM_TRY(fchown(control,0,0));SM_TRY(fchmod(control,0600));if(!S_ISCHR(ci.st_mode)||(unsigned long)btype.f_type!=BINDERFS_SUPER_MAGIC){error=ENODEV;goto done;}
    result->stage=4;
    dev_t devices[3]={0};
    for(int n=0;n<3;n++){
        struct stat node;struct binderfs_device request={0};snprintf(request.name,sizeof(request.name),"%s",names[n]);
        if(fstatat(bfs,names[n],&node,AT_SYMLINK_NOFOLLOW)){
            if(errno!=ENOENT){error=errno;goto done;}SM_TRY(ioctl(control,BINDER_CTL_ADD,&request));SM_TRY(fstatat(bfs,names[n],&node,AT_SYMLINK_NOFOLLOW));if(node.st_rdev!=makedev(request.major,request.minor)){error=EPROTO;goto done;}
        }
        if(!S_ISCHR(node.st_mode)||node.st_dev!=ci.st_dev||!major(node.st_rdev)){error=EXDEV;goto done;}
        for(int j=0;j<3;j++)if(present[j]&&node.st_rdev==stock[j].st_rdev){error=EXDEV;goto done;}
        for(int j=0;j<n;j++)if(node.st_rdev==devices[j]){error=EXDEV;goto done;}
        devices[n]=node.st_rdev;
        SM_TRY(fd=openat(bfs,names[n],O_RDWR|O_NOFOLLOW|O_CLOEXEC));struct stat opened;SM_TRY(fstat(fd,&opened));if(!pd_same_inode(&opened,&node)||opened.st_rdev!=node.st_rdev){error=ESTALE;goto done;}
        struct binder_version version={0};SM_TRY(ioctl(fd,BINDER_VERSION,&version));if(version.protocol_version!=BINDER_CURRENT_PROTOCOL_VERSION){error=EPROTO;goto done;}
        if(!n){char actual[256]={0};ssize_t label=fgetxattr(fd,"security.selinux",actual,sizeof(actual)-1);if(label<=0||strcmp(actual,binder_label)){error=EXDEV;goto done;}}
        SM_TRY(fchown(fd,n==0?1000:0,n==0?1000:0));SM_TRY(fchmod(fd,n==0?0600:0));if(!n){result->binder_dev=node.st_dev;result->binder_ino=node.st_ino;result->binder_rdev=node.st_rdev;}close(fd);fd=-1;
    }
    SM_TRY(symlinkat("binderfs/binder",dev,"binder"));result->binder_verified=1;
    result->stage=5;
    SM_TRY(host_sel=open("/sys/fs/selinux",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));struct statfs stype;SM_TRY(fstatfs(host_sel,&stype));if((uint32_t)stype.f_type!=SM_SELINUX_MAGIC){error=EXDEV;goto done;}
    for(int n=0;n<2;n++)SM_TRY(query[n]=openat(host_sel,queries[n],O_PATH|O_NOFOLLOW|O_CLOEXEC));
    result->stage=6;
    SM_TRY(sys=sm_new_tmpfs(root,"sys","size=1m,mode=0755",MS_NOEXEC));SM_TRY(fsdir=sm_make_path(sys,"fs",0755));SM_TRY(sel=sm_make_path(fsdir,"selinux",0755));char source[64];sm_fdpath(source,sizeof(source),host_sel);sm_fdpath(path,sizeof(path),sel);SM_TRY(mount(source,path,NULL,MS_BIND,NULL));close(sel);sel=-1;
    SM_TRY(sel=openat(fsdir,"selinux",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));SM_TRY(sm_readonly(sel,MS_NOEXEC));
    for(int n=0;n<2;n++)SM_TRY(sm_bind_file(query[n],sel,queries[n],0,SM_SELINUX_MAGIC));
    SM_TRY(fd=openat(sel,"enforce",O_RDONLY|O_CLOEXEC|O_NOFOLLOW));char enforce[4]={0};ssize_t count=read(fd,enforce,sizeof(enforce));close(fd);fd=-1;if(count<1||enforce[0]!='1'){error=EPERM;goto done;}result->selinux_verified=1;
    result->stage=7;
    SM_TRY(host_attr=open("/proc/self/attr/current",O_PATH|O_NOFOLLOW|O_CLOEXEC));SM_TRY(host_exec=open("/proc/self/attr/exec",O_PATH|O_NOFOLLOW|O_CLOEXEC));SM_TRY(*context_fd=open("/proc/self/attr/exec",O_WRONLY|O_NOFOLLOW|O_CLOEXEC));
    SM_TRY(proc=sm_new_tmpfs(root,"proc","size=1m,mode=0755",MS_NOEXEC));SM_TRY(self=sm_make_path(proc,"self",0755));SM_TRY(attr=sm_make_path(self,"attr",0755));SM_TRY(fd=openat(attr,"current",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0444));close(fd);fd=-1;
    SM_TRY(sm_bind_file(host_attr,attr,"current",1,PROC_SUPER_MAGIC));SM_TRY(fd=openat(attr,"exec",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0444));close(fd);fd=-1;SM_TRY(sm_bind_file(host_exec,attr,"exec",1,PROC_SUPER_MAGIC));SM_TRY(symlinkat("self",proc,"thread-self"));result->self_proc_only=1;
    result->stage=8;
    SM_TRY(data=sm_new_tmpfs(root,"data","size=1m,mode=0755",0));SM_TRY(local=sm_make_path(data,"local",0755));SM_TRY(tmp=sm_make_path(local,"tmp",0755));SM_TRY(fd=openat(tmp,"pd2425-sm-check.so",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0444));
    for(uint64_t offset=0;offset<helper_bytes;){char buffer[8192];size_t want=helper_bytes-offset>sizeof(buffer)?sizeof(buffer):(size_t)(helper_bytes-offset);ssize_t n=pread(helper,buffer,want,(off_t)offset);if(n<=0){error=n<0?errno:EIO;goto done;}for(ssize_t used=0;used<n;){ssize_t k=write(fd,buffer+used,(size_t)(n-used));if(k<0&&errno==EINTR)continue;if(k<=0){error=k<0?errno:EIO;goto done;}used+=k;}offset+=(uint64_t)n;}
    error=pv_exact_file(fd,helper_bytes,helper_sha,digest);if(error)goto done;
    const char label[]="u:object_r:system_file:s0";SM_TRY(fsetxattr(fd,"security.selinux",label,sizeof(label),0));close(fd);fd=-1;
    result->stage=10;
    SM_TRY(service=(int)syscall(SYS_openat2,root,"system/bin/servicemanager",&(struct open_how){.flags=O_RDONLY|O_CLOEXEC,.resolve=RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS},sizeof(struct open_how)));
    SM_TRY(fd=openat(tmp,"pd2425-servicemanager",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600));
    error=sm_patch_entry(service,fd);if(error)goto done;close(service);service=-1;
    SM_TRY(fchown(fd,0,0));SM_TRY(fchmod(fd,0755));const char entry_label[]="u:object_r:servicemanager_exec:s0";
    SM_TRY(fsetxattr(fd,"security.selinux",entry_label,sizeof(entry_label),0));close(fd);fd=-1;
    SM_TRY(fd=openat(tmp,"pd2425-servicemanager",O_RDONLY|O_CLOEXEC|O_NOFOLLOW));
    SM_TRY(bin=sm_directory(root,"system/bin"));SM_TRY(sm_bind_entry(fd,bin));close(fd);fd=-1;close(bin);bin=-1;result->entry_verified=1;
    sm_fdpath(path,sizeof(path),data);SM_TRY(mount(NULL,path,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL));struct statvfs readonly;SM_TRY(fstatvfs(data,&readonly));if(!(readonly.f_flag&ST_RDONLY)){error=EPROTO;goto done;}result->helper_verified=1;result->stage=9;
done:
    {int descriptors[]={dev,bfs,control,fd,sys,fsdir,sel,host_sel,query[0],query[1],proc,self,attr,host_attr,host_exec,service,bin,data,local,tmp};for(unsigned n=0;n<sizeof(descriptors)/sizeof(descriptors[0]);n++)if(descriptors[n]>=0)close(descriptors[n]);}
    if(error){if(*context_fd>=0){close(*context_fd);*context_fd=-1;}errno=error;return -1;}return 0;
#undef SM_TRY
}
#endif
