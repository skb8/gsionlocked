/* Bootstrap only: immutable GSI system/runtime libraries; no vendor or host paths. */
#ifndef PD2425_PREVIEW_LINKERCONFIG_H
#define PD2425_PREVIEW_LINKERCONFIG_H
#include <sys/statvfs.h>
#include <sys/xattr.h>
static const char pv_bootstrap_config[] =
"# gsionlocked PD2425 bootstrap; not a full Android linker configuration\n"
"dir.bootstrap = /system/bin\n"
"dir.bootstrap = /apex/com.android.runtime/bin\n"
"[bootstrap]\n"
"namespace.default.isolated = true\n"
"namespace.default.search.paths = /apex/com.android.runtime/lib64/bionic:/system/lib64:/system/system_ext/lib64:/apex/com.android.runtime/lib64\n"
"namespace.default.permitted.paths = /apex/com.android.runtime/lib64:/apex/com.android.runtime/bin:/system/lib64:/system/system_ext/lib64\n";

static const char pv_smoke_config[] =
"dir.bootstrap = /system/bin\n"
"dir.bootstrap = /apex/com.android.runtime/bin\n"
"[bootstrap]\n"
"namespace.default.isolated = true\n"
"namespace.default.search.paths = /system/lib64/bootstrap:/system/lib64:/system/system_ext/lib64:/apex/com.android.runtime/lib64\n"
"namespace.default.permitted.paths = /system/lib64/bootstrap:/apex/com.android.runtime/lib64:/apex/com.android.runtime/bin:/system/lib64:/system/system_ext/lib64:/data/local/tmp\n";
static int pv_create_linkerconfig_body(int root,const char *body,size_t bytes,int label_private){
    struct open_how how={.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC,.resolve=RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS};
    int dir=(int)syscall(SYS_openat2,root,"linkerconfig",&how,sizeof(how));if(dir<0)return -1;
    char target[64];snprintf(target,sizeof(target),"/proc/self/fd/%d",dir);
    int error=0,file=-1;
    if(mount("tmpfs",target,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=64k,mode=0755")){error=errno;goto done;}
    close(dir);dir=(int)syscall(SYS_openat2,root,"linkerconfig",&how,sizeof(how));if(dir<0){error=errno;goto done;}
    if(label_private){const char label[]="u:object_r:system_file:s0";if(fsetxattr(dir,"security.selinux",label,sizeof(label),0)){error=errno;goto done;}}
    file=openat(dir,"ld.config.txt",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0444);
    if(file<0){error=errno;goto done;}
    for(size_t n=0;n<bytes;){
        ssize_t written=write(file,body+n,bytes-n);
        if(written<0&&errno==EINTR)continue;
        if(written<=0){error=written<0?errno:EIO;goto done;}n+=(size_t)written;
    }
    if(label_private){const char label[]="u:object_r:system_linker_config_file:s0";if(fsetxattr(file,"security.selinux",label,sizeof(label),0)){error=errno;goto done;}}
    close(file);file=-1;snprintf(target,sizeof(target),"/proc/self/fd/%d",dir);
    if(mount(NULL,target,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)){error=errno;goto done;}
    struct statvfs fs;if(fstatvfs(dir,&fs)){error=errno;goto done;}
    if(!(fs.f_flag&ST_RDONLY)){error=EPROTO;goto done;}
    /* Verify actual write rejection while still privileged, not just a flag. */
    file=openat(dir,"ld.config.txt",O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
    if(file>=0){error=EPROTO;goto done;}if(errno!=EROFS){error=errno;goto done;}
done:
    if(file>=0)close(file);
    if(dir>=0)close(dir);
    if(error){errno=error;return -1;}return 0;
}
static int pv_create_linkerconfig(int root){return pv_create_linkerconfig_body(root,pv_bootstrap_config,sizeof(pv_bootstrap_config)-1,0);}
#endif
