// SPDX-License-Identifier: GPL-2.0-only
// Private mount namespace only. No stop/start, property writes or reboot.
#define _GNU_SOURCE
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/system_properties.h>
#include <sys/ioctl.h>
#include <linux/android/binderfs.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <sys/inotify.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <time.h>
#include <sys/syscall.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <glob.h>
static int module_overlay146(const char *root){(void)root;return 0;}
#ifdef TEMPGSI_HAL_PROFILE151
#include "hal_identity151.h"
#include "hal_specs151.generated.h"
static const struct hal_identity151 *child_hal151=NULL;
#endif
static int zygote_socket=-1;
static int usap_socket=-1;
static int child_notice=-1;
static int run_as_system=0;
static int run_as_keystore=0;
static int run_as_media=0;
static const char *child_exec_context=NULL;
static int deny_block_nodes=0;
static int deny_bpf=0;
static int dnsproxy_socket=-1,mdns_socket=-1,fwmark_socket=-1;
static int boot_kmsg_fd=-1;
static int lmkd_socket=-1;
static int deny_process_kill=0;
static int physical_display=0;
static int unlimited_session=0;
static int wifi_takeover=0;
static int radio_takeover139=0;
static pid_t session_sf_pid=-1;
static const char controller_install_command[]=
    "n=0; while [ \"$(getprop sys.boot_completed)\" != 1 ] && [ $n -lt 80 ]; do sleep 0.5; n=$((n+1)); done; "
    "[ \"$(getprop sys.boot_completed)\" = 1 ] || exit 2; "
    "{ installed=$(pm path --user 0 dev.tempgsi.controller 2>/dev/null); "
    "case \"$installed\" in package:/data/app/*/base.apk) "
    "installed=${installed#package:}; expected=$(sha256sum /data/local/tmp/controller.apk); actual=$(sha256sum \"$installed\"); "
    "if [ -n \"$actual\" ] && [ \"${expected%% *}\" = \"${actual%% *}\" ]; then echo 'Success (existing identical APK preserved)'; exit 0; fi;; esac; "
    "exec timeout 25 pm install --user 0 -r /data/local/tmp/controller.apk; } > /data/local/tmp/controller-install.txt 2>&1";
static char phone_log_source[512];
struct apex_data_metadata {char path[512],context[256];uid_t uid;gid_t gid;mode_t mode;};
static struct apex_data_metadata apex_data[192];
static unsigned apex_data_count=0;
static pid_t cleanup_owner=0;
static int private_root_ready=0;
static void cleanup_private_children(void);
static int child(char *const args[]);
static void die(const char *s);
static void lmkd_no_kill_filter(void){
    struct sock_filter instructions[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_kill,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_tkill,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_tgkill,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_pidfd_send_signal,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_process_madvise,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_process_vm_writev,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_ptrace,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={.len=sizeof(instructions)/sizeof(instructions[0]),.filter=instructions};
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))_exit(96);
    errno=0;if(kill(getpid(),0)!=-1||errno!=EPERM)_exit(97);
    puts("PRIVATE_LMKD_SIGNAL_AND_REMOTE_MEMORY_FILTER_VERIFIED_NO_PROCESS_KILLS");
}
static void private_bpf_loader_filter(void){
    struct sock_filter instructions[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_perf_event_open,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_bpf,0,6),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K,BPF_OBJ_GET,0,4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,BPF_OBJ_GET_INFO_BY_FD,3,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,BPF_BTF_LOAD,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,BPF_MAP_FREEZE,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={.len=sizeof(instructions)/sizeof(instructions[0]),.filter=instructions};
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))_exit(96);
    puts("PRIVATE_BPF_LOADER_FILTER_NO_ATTACH_NO_GLOBAL_FD_LOOKUP");
}
static void network_bpf_filter(void){
    struct sock_filter instructions[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_bpf,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={.len=sizeof(instructions)/sizeof(instructions[0]),.filter=instructions};
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))_exit(96);
    puts("PRIVATE_NETD_BPF_SYSCALLS_DENIED_NO_HOST_CGROUP_ATTACH");
}
static int private_service_socket(const char *name,gid_t group){
    struct sockaddr_un address={.sun_family=AF_UNIX};snprintf(address.sun_path,sizeof(address.sun_path),"/dev/socket/%s",name);
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0||bind(fd,(struct sockaddr*)&address,sizeof(address))||chown(address.sun_path,0,group)||chmod(address.sun_path,0660))die("private netd socket");return fd;
}
static void block_device_node_filter(void){
    struct sock_filter instructions[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_mknodat,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_STMT(BPF_ALU|BPF_AND|BPF_K,S_IFMT),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,S_IFBLK,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={.len=sizeof(instructions)/sizeof(instructions[0]),.filter=instructions};
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))_exit(96);
    errno=0;if(mknod("/dev/tempgsi-block-node-must-not-exist",S_IFBLK|0600,makedev(7,0))!=-1||errno!=EPERM)_exit(97);
    if(mkfifo("/dev/tempgsi-fifo-filter-test",0600)||unlink("/dev/tempgsi-fifo-filter-test"))_exit(98);
    puts("PRIVATE_VOLD_BLOCK_NODE_FILTER_VERIFIED");
}
static void cleanup_on_exit(void){if(private_root_ready&&getpid()==cleanup_owner)cleanup_private_children();}
static const char *base="/data/local/tmp/tempgsi-evox154/root";
static void die(const char *s){perror(s);exit(20);}
static void save_property(void *file,const char *name,const char *value,uint32_t serial){
    (void)serial;FILE *out=file;
    if(fwrite(name,1,strlen(name)+1,out)!=strlen(name)+1||fwrite(value,1,strlen(value)+1,out)!=strlen(value)+1)die("save property");
}
static void each_property(const prop_info *info,void *file){__system_property_read_callback(info,save_property,file);}
static void subpath(char *out,const char *suffix){snprintf(out,512,"%s%s",base,suffix);}
static void bind_readonly(const char *source,const char *target){
    if(mount(source,target,NULL,MS_BIND,NULL)){fprintf(stderr,"BIND_FAILED_SOURCE=%s_TARGET=%s\n",source,target);die("bind");}
    if(mount(NULL,target,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL))die("readonly bind");
}
static void secure_private_config(const char *path,const char *context){
    struct stat info;if(lstat(path,&info)||!S_ISREG(info.st_mode))die("private configuration must be regular file");
    if(chown(path,0,0)||chmod(path,0644)||lsetxattr(path,"security.selinux",context,strlen(context)+1,0))die("private configuration owner/mode/label");
}
static void inherit_private_directory_label(const char *host_path){
    char context[512],target[512];ssize_t size=getxattr(host_path,"security.selinux",context,sizeof(context));
    if(size<=0)die("host directory label query");subpath(target,host_path);
    if(lsetxattr(target,"security.selinux",context,size,0))die("private directory label");
}
static void snapshot_apex_directory(const char *path){
    if(apex_data_count>=sizeof(apex_data)/sizeof(apex_data[0]))die("APEX metadata capacity");
    struct apex_data_metadata *entry=&apex_data[apex_data_count++];snprintf(entry->path,sizeof(entry->path),"%s",path);
    entry->uid=0;entry->gid=1000;entry->mode=0771;strcpy(entry->context,"u:object_r:system_data_file:s0");
    struct stat info;if(!lstat(path,&info)&&S_ISDIR(info.st_mode)){
        entry->uid=info.st_uid;entry->gid=info.st_gid;entry->mode=info.st_mode&07777;
        ssize_t length=lgetxattr(path,"security.selinux",entry->context,sizeof(entry->context)-1);
        if(length<=0)die("APEX host directory label");entry->context[length]=0;
    }
}
static void snapshot_apex_data_metadata(void){
    const char *parents[]={"/data/misc/apexdata","/data/misc_de/0/apexdata","/data/misc_ce/0/apexdata"};
    char apex_root[512];subpath(apex_root,"/apex");
    for(unsigned i=0;i<sizeof(parents)/sizeof(parents[0]);i++){
        snapshot_apex_directory(parents[i]);DIR *directory=opendir(apex_root);if(!directory)die("APEX data names");struct dirent *module;
        while((module=readdir(directory))){if(strncmp(module->d_name,"com.",4)||strlen(module->d_name)>90||strstr(module->d_name,".."))continue;
            char path[512];snprintf(path,sizeof(path),"%s/%.90s",parents[i],module->d_name);snapshot_apex_directory(path);
        }closedir(directory);
    }
    // Directory metadata only: AdbDebuggingManager needs its own empty state
    // directory. Never copy host adb_keys or an authorization database.
    snapshot_apex_directory("/data/misc/adb");
}
static void create_private_apex_data_directories(void){
    for(unsigned i=0;i<apex_data_count;i++){
        struct apex_data_metadata *entry=&apex_data[i];
        if((mkdir(entry->path,entry->mode)&&errno!=EEXIST)||chown(entry->path,entry->uid,entry->gid)||chmod(entry->path,entry->mode)||lsetxattr(entry->path,"security.selinux",entry->context,strlen(entry->context)+1,0))die("private APEX directory metadata");
    }
    printf("PRIVATE_APEX_DATA_DIRECTORIES_READY=%u_METADATA_ONLY_NO_HOST_CONTENTS\n",apex_data_count);
}
static void prepare_init_directories(const char *filename){
    FILE *input=fopen(filename,"r");if(!input)die("GSI directory declarations");
    char line[2048],command[32],path[512],user[64],group[64];unsigned mode,count=0;
    while(fgets(line,sizeof(line),input)){
        if(sscanf(line,"%31s %511s %o %63s %63s",command,path,&mode,user,group)!=5||strcmp(command,"mkdir"))continue;
        if(strncmp(path,"/data/",6)&&strncmp(path,"/metadata/",10))continue;
        if(strstr(path,"..")||strchr(path,'$')||mode>07777)continue;
        struct passwd *owner=getpwnam(user);if(!owner){printf("PRIVATE_INIT_UNKNOWN_USER=%s\n",user);continue;}uid_t uid=owner->pw_uid;
        struct group *members=getgrnam(group);if(!members){printf("PRIVATE_INIT_UNKNOWN_GROUP=%s\n",group);continue;}gid_t gid=members->gr_gid;
        if((mkdir(path,mode)&&errno!=EEXIST)||chown(path,uid,gid)||chmod(path,mode))die("GSI private directory setup");count++;
    }
    fclose(input);printf("PRIVATE_INIT_DIRECTORIES=%u_SOURCE=%s\n",count,filename);
}
static void private_unavailable_fingerprint(void){
    const char *target="/vendor/etc/permissions/qti_fingerprint_interface.xml";
    FILE *input=fopen(target,"r");if(!input)die("guest feature source");char xml[8192];
    size_t length=fread(xml,1,sizeof(xml)-1,input);if(ferror(input)||!feof(input))die("guest feature source size");fclose(input);xml[length]=0;
    char *end=strstr(xml,"</permissions>");if(!end)die("guest feature source format");
    const char *source="/data/local/tmp/guest-fingerprint-feature.xml";
    FILE *output=fopen(source,"w");if(!output)die("private feature file");
    if(fwrite(xml,1,(size_t)(end-xml),output)!=(size_t)(end-xml)||fputs("<unavailable-feature name=\"android.hardware.fingerprint\"/>\n",output)<0||fputs(end,output)<0||fclose(output))die("private feature write");
    const char *context="u:object_r:system_file:s0";
    if(chmod(source,0644)||lsetxattr(source,"security.selinux",context,strlen(context)+1,0))die("private feature label");
    bind_readonly(source,target);puts("PRIVATE_FINGERPRINT_FEATURE_UNAVAILABLE_NO_HOST_HAL_NO_RETRY_STORM");
}
static void prepare_private_data_mirror(void){
    const char *directories[]={"/data_mirror/data_ce","/data_mirror/data_de","/data_mirror/misc_ce","/data_mirror/misc_de","/data_mirror/data_ce/null","/data_mirror/data_de/null","/data_mirror/misc_ce/null","/data_mirror/misc_de/null","/data_mirror/cur_profiles","/data_mirror/ref_profiles","/data/misc/profiles","/data/misc/profiles/cur","/data/misc/profiles/ref"};
    for(unsigned i=0;i<sizeof(directories)/sizeof(directories[0]);i++)if(mkdir(directories[i],0700)&&errno!=EEXIST)die("private data mirror directory");
    const char *sources[]={"/data/user","/data/user_de","/data/misc_ce","/data/misc_de","/data/misc/profiles/cur","/data/misc/profiles/ref"};
    const char *targets[]={"/data_mirror/data_ce/null","/data_mirror/data_de/null","/data_mirror/misc_ce/null","/data_mirror/misc_de/null","/data_mirror/cur_profiles","/data_mirror/ref_profiles"};
    for(unsigned i=0;i<sizeof(sources)/sizeof(sources[0]);i++)if(mount(sources[i],targets[i],NULL,MS_BIND|MS_REC,NULL))die("private data mirror bind");
    puts("PRIVATE_DATA_MIRROR_READY_OWN_TMPFS_ONLY");
}
static void label_aconfig_tree(const char *path){
    if(strncmp(path,"/metadata/aconfig",17))die("aconfig label scope");
    struct stat info;if(lstat(path,&info))die("aconfig metadata stat");if(S_ISLNK(info.st_mode))die("aconfig unexpected symlink");
    const char *context=!strncmp(path,"/metadata/aconfig/flags",23)?"u:object_r:aconfig_storage_flags_metadata_file:s0":"u:object_r:aconfig_storage_metadata_file:s0";
    if(lsetxattr(path,"security.selinux",context,strlen(context)+1,0))die("aconfig metadata label");
    if(S_ISDIR(info.st_mode)){DIR *directory=opendir(path);if(!directory)die("aconfig metadata directory");struct dirent *entry;
        while((entry=readdir(directory))){if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;char next[1024];if(snprintf(next,sizeof(next),"%s/%s",path,entry->d_name)>=(int)sizeof(next))die("aconfig metadata length");label_aconfig_tree(next);}closedir(directory);}
}
static pid_t find_private_system_server(void){
    struct stat root;if(stat("/",&root))return -1;DIR *proc=opendir("/proc");if(!proc)return -1;struct dirent *entry;pid_t found=-1;
    while((entry=readdir(proc))){int pid=atoi(entry->d_name);if(pid<=1)continue;char path[128],name[64];struct stat candidate;
        snprintf(path,sizeof(path),"/proc/%d/root",pid);if(stat(path,&candidate)||candidate.st_dev!=root.st_dev||candidate.st_ino!=root.st_ino)continue;
        snprintf(path,sizeof(path),"/proc/%d/comm",pid);FILE *input=fopen(path,"r");if(!input)continue;name[0]=0;fgets(name,sizeof(name),input);fclose(input);
        if(!strcmp(name,"system_server\n")){found=pid;break;}
    }closedir(proc);return found;
}
static int bluetooth165,bt_address165=-1,camera166,fingerprint167,gatekeeper169;
static const char *calibration166[]={"/efs/FactoryApp/camera_ois_gyro_cal","/efs/FactoryApp/camera_tilt_calibration_info_1_2","/efs/FactoryApp/camera_tilt_calibration_info_3_1","/mnt/vendor/efs/camera/camera_tilt_calibration_info_1_2","/mnt/vendor/efs/camera/camera_tilt_calibration_info_3_1"};
static pid_t start_private_native_service(const char *binary,pid_t *supervisor){
    int notice[2];if(pipe2(notice,O_CLOEXEC))die("native service PID pipe");
    *supervisor=fork();if(*supervisor<0)die("native service supervisor");
    if(!*supervisor){close(notice[0]);child_notice=notice[1];deny_block_nodes=!strncmp(binary,"/system/bin/vold ",17);

#ifdef TEMPGSI_HAL_PROFILE151
        for(size_t i=0;i<sizeof(hal_specs151)/sizeof(hal_specs151[0]);i++){
            if(strcmp(binary,hal_specs151[i].binary)&&!(gatekeeper169&&!strcmp(binary,"/system/bin/gatekeeperd /data/misc/gatekeeper")&&!strcmp(hal_specs151[i].name,"gatekeeperd")))continue;
            child_hal151=&hal_specs151[i];child_exec_context=child_hal151->context;

            printf("PRIVATE_HAL_PROFILE151_SERVICE=%s UID=%u GID=%u\n",child_hal151->name,(unsigned)child_hal151->uid,(unsigned)child_hal151->groups[0]);
            // Exec the HAL itself: do not consume its SELinux exec transition on sh.
            char *hal_args[]={(char*)child_hal151->binary,!strcmp(binary,"/vendor/bin/vndservicemanager")?"/dev/vndbinder":!strcmp(child_hal151->name,"gatekeeperd")?"/data/misc/gatekeeper":NULL,NULL};int result=child(hal_args);
            printf("PRIVATE_HAL_PROFILE151_EXIT name=%s result=%d\n",child_hal151->name,result);_exit(result);
        }
#endif
        if(!strcmp(binary,"/system/bin/keystore2 /data/misc/keystore")){
            const char *label="u:object_r:keystore_data_file:s0";
            if(chown("/data/misc/keystore",1017,1017)||chmod("/data/misc/keystore",0700)||lsetxattr("/data/misc/keystore","security.selinux",label,strlen(label)+1,0))die("private keystore metadata");
            child_exec_context="u:r:keystore:s0";run_as_keystore=1;
            char *args[]={"/system/bin/keystore2","/data/misc/keystore",NULL};
            int result=child(args);printf("PRIVATE_KEYSTORE_PROPER_DOMAIN_EXIT=%d\n",result);_exit(result);
        }
        if(!strcmp(binary,"/system/bin/netd")){gid_t net_admin=3005;if(setgroups(1,&net_admin))die("private netd init groups");deny_bpf=1;dnsproxy_socket=private_service_socket("dnsproxyd",3003);mdns_socket=private_service_socket("mdns",1000);fwmark_socket=private_service_socket("fwmarkd",3003);}
        // Match this GSI's init .rc identities. These services use only the
        // private Binder/hwbinder; no host codec service is exposed to apps.
        if(!strcmp(binary,"/apex/com.android.media.swcodec/bin/mediaswcodec")){run_as_media=1;child_exec_context="u:r:mediacodec:s0";}
        else if(!strcmp(binary,"/system/bin/mediaextractor")){run_as_media=2;child_exec_context="u:r:mediaextractor:s0";}
        else if(!strcmp(binary,"/system/bin/mediaserver64")){run_as_media=3;child_exec_context="u:r:mediaserver:s0";}
        if(run_as_media){char *args[]={(char*)binary,NULL};int result=child(args);printf("PRIVATE_MEDIA_SERVICE_EXIT binary=%s result=%d\n",binary,result);_exit(result);}
        if(!strcmp(binary,"/system/bin/lmkd")){
            deny_process_kill=1;deny_bpf=1;
            struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/dev/socket/lmkd");
            lmkd_socket=socket(AF_UNIX,SOCK_SEQPACKET,0);int passcred=1;
            if(lmkd_socket<0||setsockopt(lmkd_socket,SOL_SOCKET,SO_PASSCRED,&passcred,sizeof(passcred))||bind(lmkd_socket,(struct sockaddr*)&address,sizeof(address))||chown(address.sun_path,1000,1000)||chmod(address.sun_path,0660))die("private lmkd socket");
            const char *context="u:object_r:lmkd_socket:s0";if(lsetxattr(address.sun_path,"security.selinux",context,strlen(context)+1,0))die("private lmkd socket label");
        }
        char command[1200];snprintf(command,sizeof(command),"%s; %s exec %s",!strncmp(binary,"/vendor/",8)?"export LD_LIBRARY_PATH=/data/local/tmp/vendor-compat-libs":"while read command name value; do [ \"$command\" = export ] || exit 2; export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; [ -n \"$BOOTCLASSPATH\" ] && [ -n \"$DEX2OATBOOTCLASSPATH\" ] || exit 4; export LD_PRELOAD=/data/local/tmp/private-selinux-mount.so",!strcmp(binary,"/apex/com.android.art/bin/artd")?"export LD_PRELOAD=/data/local/tmp/artd-session.so:/data/local/tmp/private-selinux-mount.so;":"",binary);char *args[]={"/system/bin/sh","-c",command,NULL};int result=child(args);printf("PRIVATE_NATIVE_SERVICE_EXIT binary=%s result=%d\n",binary,result);_exit(result);}
    close(notice[1]);pid_t pid;if(read(notice[0],&pid,sizeof(pid))!=sizeof(pid)||pid<=1)die("native service PID receive");close(notice[0]);
    printf("PRIVATE_NATIVE_SERVICE_PID=%d_BINARY=%s\n",pid,binary);return pid;
}
static int child(char *const args[]){
    pid_t pid=fork();int status;
    if(pid<0)die("fork");
    if(!pid){
        if(deny_block_nodes)block_device_node_filter();
        if(deny_bpf==1)network_bpf_filter();else if(deny_bpf==2)private_bpf_loader_filter();
        if(deny_process_kill)lmkd_no_kill_filter();
        if(run_as_system&&(setgid(1000)||setuid(1000)))_exit(91);
        // An init-launched Android service inherits only stdio and its named sockets.
        // Close launcher descriptors before exec, preserving the explicit Zygote sockets.
        DIR *fds=opendir("/proc/self/fd");if(!fds)_exit(92);struct dirent *fd_entry;
        while((fd_entry=readdir(fds))){int fd=atoi(fd_entry->d_name);if(fd>2&&fd!=dirfd(fds)&&fd!=zygote_socket&&fd!=usap_socket&&fd!=dnsproxy_socket&&fd!=mdns_socket&&fd!=fwmark_socket&&fd!=boot_kmsg_fd&&fd!=lmkd_socket)close(fd);}
        closedir(fds);
        if(zygote_socket>=0||child_exec_context){
            // ART duplicates stderr internally. An ADB socket here would become an
            // unnamed socket in Zygote's fork allowlist; init normally uses /dev/null.
            int null_fd=open("/dev/null",O_RDWR);if(null_fd<0)_exit(93);
            for(int fd=0;fd<3;fd++)if(dup2(null_fd,fd)<0)_exit(94);if(null_fd>2)close(null_fd);
        }
        char socket_env[64];snprintf(socket_env,sizeof(socket_env),"ANDROID_SOCKET_zygote=%d",zygote_socket);
        char usap_env[80];snprintf(usap_env,sizeof(usap_env),"ANDROID_SOCKET_usap_pool_primary=%d",usap_socket);
        char dns_env[80],mdns_env[80],fwmark_env[80];snprintf(dns_env,sizeof(dns_env),"ANDROID_SOCKET_dnsproxyd=%d",dnsproxy_socket);snprintf(mdns_env,sizeof(mdns_env),"ANDROID_SOCKET_mdns=%d",mdns_socket);snprintf(fwmark_env,sizeof(fwmark_env),"ANDROID_SOCKET_fwmarkd=%d",fwmark_socket);
        char kmsg_env[80];snprintf(kmsg_env,sizeof(kmsg_env),"ANDROID_FILE__dev_kmsg=%d",boot_kmsg_fd);
        char lmkd_env[80];snprintf(lmkd_env,sizeof(lmkd_env),"ANDROID_SOCKET_lmkd=%d",lmkd_socket);
        if(child_exec_context){
            int context_fd=open("/proc/self/attr/exec",O_WRONLY|O_CLOEXEC);
            size_t context_size=strlen(child_exec_context);
            if(context_fd<0||write(context_fd,child_exec_context,context_size)!=(ssize_t)context_size)_exit(95);
            close(context_fd);
        }
        if(run_as_keystore){gid_t groups[]={1017,3009,1007};if(setgroups(3,groups)||setgid(1017)||setuid(1017))_exit(96);}
        if(run_as_media==1){gid_t groups[]={1006,1026,1031};if(setgroups(3,groups)||setgid(1006)||setuid(1046))_exit(96);}
        else if(run_as_media==2){gid_t groups[]={1026,1031};if(setgroups(2,groups)||setgid(1026)||setuid(1040))_exit(96);}
        else if(run_as_media==3){gid_t groups[]={1005,1006,3003,3002,3001,3007,1026,1031};if(setgroups(8,groups)||setgid(1005)||setuid(1013))_exit(96);}
#ifdef TEMPGSI_HAL_PROFILE151
        if(child_hal151&&(!strcmp(child_hal151->binary,"/system/bin/hw/android.hardware.bluetooth.audio-service-system")||!strcmp(child_hal151->binary,"/system/bin/cameraserver")||!strcmp(child_hal151->name,"sec-camera-provider"))&&syscall(SYS_ioprio_set,1,0,(1<<13)|4))_exit(99);
        if(child_hal151&&(hal_identity151_apply(child_hal151)||hal_identity151_verify(child_hal151)))_exit(98);
#endif
        const char *library_env="LD_LIBRARY_PATH=/apex/com.android.runtime/lib64/bionic:/apex/com.android.art/lib64:/apex/com.android.i18n/lib64:/apex/com.android.conscrypt/lib64:/apex/com.android.os.statsd/lib64:/apex/com.android.tethering/lib64:/system/lib64";
        const char *preload_env=child_exec_context?"LD_PRELOAD=/data/local/tmp/private-selinux-mount.so":NULL;
#ifdef TEMPGSI_HAL_PROFILE151
        if(child_hal151&&(!strncmp(args[0],"/vendor/",8)||!strcmp(child_hal151->name,"sec-camera-provider")||!strcmp(child_hal151->name,"fingerprint167"))){library_env="LD_LIBRARY_PATH=/data/local/tmp/vendor-compat-libs";preload_env=!strcmp(args[0],"/vendor/bin/vndservicemanager")?"LD_PRELOAD=/data/local/tmp/camera-runtime166/private-selinux-mount.so":NULL;if(!strcmp(child_hal151->name,"vendor.gatekeeper-1-0"))preload_env="LD_PRELOAD=/data/local/tmp/camera-runtime166/gatekeeper-isolation169.so:/data/local/tmp/camera-runtime166/private-selinux-mount.so";}
#endif
        char *const env[]={"PATH=/system/bin","ANDROID_ROOT=/system","ANDROID_DATA=/data","EXTERNAL_STORAGE=/storage/emulated/0","ASEC_MOUNTPOINT=/mnt/asec","ANDROID_ART_ROOT=/apex/com.android.art","ANDROID_I18N_ROOT=/apex/com.android.i18n","ANDROID_RUNTIME_ROOT=/apex/com.android.runtime","ANDROID_TZDATA_ROOT=/apex/com.android.tzdata",(char*)library_env,socket_env,usap_env,dns_env,mdns_env,fwmark_env,kmsg_env,lmkd_env,(char*)preload_env,NULL};
        alarm(physical_display?(unlimited_session?0:120):35);execve(args[0],args,env);perror(args[0]);_exit(127);
    }
    if(child_notice>=0){if(write(child_notice,&pid,sizeof(pid))!=sizeof(pid))die("child PID notice");close(child_notice);child_notice=-1;}
    if(physical_display&&unlimited_session){
        // The external guardian owns this session's deadline and cgroup kill.
        // Sleep until the service exits instead of waking each supervisor at
        // 10 Hz for the entire session. EINTR does not mean child termination.
        while(waitpid(pid,&status,0)!=pid)if(errno!=EINTR)die("wait for supervised service");
        return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
    }
    for(unsigned tick=0;;tick++){
        pid_t done=waitpid(pid,&status,WNOHANG);
        if(done==pid)break;if(done<0&&errno!=EINTR)die("waitpid");
        if(!(physical_display&&unlimited_session)&&tick>=(physical_display?1200U:350U)){kill(pid,SIGKILL);while(waitpid(pid,&status,0)<0)if(errno!=EINTR)die("reap timed out child");return 124;}
        usleep(100000);
    }
    return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
}
static int probe_zygote(int start_system_server){
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/dev/socket/zygote");
    zygote_socket=socket(AF_UNIX,SOCK_STREAM,0);if(zygote_socket<0)die("zygote socket");
    if(bind(zygote_socket,(struct sockaddr*)&address,sizeof(address)))die("zygote bind");
    if(chown(address.sun_path,0,1000)||chmod(address.sun_path,0660))die("zygote socket permissions");
    usap_socket=socket(AF_UNIX,SOCK_STREAM,0);if(usap_socket<0)die("usap socket");
    strcpy(address.sun_path,"/dev/socket/usap_pool_primary");
    if(bind(usap_socket,(struct sockaddr*)&address,sizeof(address)))die("usap bind");
    strcpy(address.sun_path,"/dev/socket/zygote");
    int notice[2];if(pipe2(notice,O_CLOEXEC))die("zygote PID pipe");
    pid_t supervisor=fork();if(supervisor<0)die("zygote fork");
    if(!supervisor){
        close(notice[0]);child_notice=notice[1];
        if(setpgid(0,0))die("zygote process group");
        char command[2048];snprintf(command,sizeof(command),"while read command name value; do [ \"$command\" = export ] || exit 2; export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export LD_PRELOAD=/data/local/tmp/private-selinux-mount.so; exec /system/bin/app_process64 -Xzygote -XjdwpProvider:none -Xusejit:%s -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx512m /system/bin --zygote %s --abi-list=arm64-v8a --socket-name=zygote",physical_display?"true":"false",start_system_server?"--start-system-server":"");
        if(physical_display)puts("PRIVATE_DAILY_ZYGOTE_JIT_ENABLED");
        char *args[]={"/system/bin/sh","-c",command,NULL};
        _exit(child(args));
    }
    close(notice[1]);pid_t zygote_pid;
    if(read(notice[0],&zygote_pid,sizeof(zygote_pid))!=sizeof(zygote_pid)||zygote_pid<=1)die("zygote PID receive");close(notice[0]);
    close(zygote_socket);zygote_socket=-1;
    close(usap_socket);usap_socket=-1;
    int result=12,status=0;
    for(int retry=0;retry<50;retry++){
        if(waitpid(supervisor,&status,WNOHANG)==supervisor){printf("LINEAGE_ZYGOTE_EXIT_STATUS=%d\n",status);return result;}
        pid_t query=fork();if(query<0)die("query fork");
        if(!query){
        if(setgid(1000)||setuid(1000))_exit(2);
        int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)die("query socket");
        struct timeval timeout={.tv_sec=1};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        if(!connect(fd,(struct sockaddr*)&address,sizeof(address))){
            const char query[]="1\n--query-abi-list\n";uint32_t length=0;char abi[64]={0};
            if(write(fd,query,sizeof(query)-1)==sizeof(query)-1&&recv(fd,&length,4,MSG_WAITALL)==4){
                length=ntohl(length);
                if(length>0&&length<sizeof(abi)&&recv(fd,abi,length,MSG_WAITALL)==length&&!strcmp(abi,"arm64-v8a")){
                    printf("LINEAGE_ZYGOTE_PRELOAD_AND_ABI_QUERY_OK=%s\n",abi);close(fd);_exit(0);
                }
            }
        }
        close(fd);_exit(1);
        }
        int query_status;while(waitpid(query,&query_status,0)<0)if(errno!=EINTR)die("query wait");
        if(WIFEXITED(query_status)&&WEXITSTATUS(query_status)==0){result=0;break;}
        usleep(300000);
    }
    if(start_system_server&&!result){
        if(physical_display){
            pid_t wake=fork();if(wake<0)die("guest bounded display wake fork");
            if(!wake){char *args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/balanced198.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx64m /system/bin GuestDisplayWake",NULL};run_as_system=1;_exit(child(args));}
        }
        if(physical_display&&!access("/data/local/tmp/controller.apk",F_OK)){
            pid_t installer=fork();if(installer<0)die("guest controller install fork");
            if(!installer){char *args[]={"/system/bin/sh","-c",(char*)controller_install_command,NULL};_exit(child(args));}
        }
        if(physical_display){
            if(!unlimited_session){pid_t tracer=fork();if(tracer<0)die("stack diagnostic fork");if(!tracer){sleep(15);pid_t server=find_private_system_server();if(server>1){printf("PRIVATE_SYSTEMSERVER_STACK_REQUEST_PID=%d\n",server);kill(server,SIGQUIT);}sleep(5);int rc=0;for(int round=0;round<2;round++){char *capture[]={"/system/bin/sh","-c","/system/bin/screencap -p /data/local/tmp/interface-screen.png; /system/bin/dumpsys user > /data/local/tmp/interface-users.txt; /system/bin/dumpsys activity activities > /data/local/tmp/interface-activities.txt; /system/bin/dumpsys input > /data/local/tmp/interface-input.txt; /system/bin/dumpsys display > /data/local/tmp/interface-display.txt; /system/bin/dumpsys SurfaceFlinger --displays > /data/local/tmp/interface-surface.txt",NULL};rc=child(capture);printf("PRIVATE_INTERFACE_CAPTURE_ROUND=%d_RESULT=%d\n",round,rc);if(!round)sleep(25);}_exit(rc);}}}
        // AudioPolicy itself waits for ActivityManager. Probe concurrently only
        // after starting the real SystemServer; a pre-Zygote readiness gate deadlocks.
        pid_t audio_check=fork();if(audio_check<0)die("audio policy check fork");
        if(!audio_check){
            char *audio_args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/runtime-smoke.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin AudioSmoke",NULL};
            run_as_system=1;int audio_result=child(audio_args);
            printf("PRIVATE_AUDIO_POLICY_PREFLIGHT_RESULT=%d\n",audio_result);_exit(audio_result);
        }
        char children_path[128],children[512];snprintf(children_path,sizeof(children_path),"/proc/%d/task/%d/children",zygote_pid,zygote_pid);
        FILE *input=fopen(children_path,"r");if(input){size_t n=fread(children,1,sizeof(children)-1,input);children[n]=0;fclose(input);printf("PRIVATE_ZYGOTE_CHILDREN=%s\n",children);}
        if(physical_display&&unlimited_session){
            pid_t server=-1;for(int attempt=0;attempt<60&&server<=1;attempt++){server=find_private_system_server();if(server<=1)sleep(1);}
            if(server>1){int descriptor=syscall(SYS_pidfd_open,server,0);if(descriptor<0)die("private SystemServer pidfd");
                int display=syscall(SYS_pidfd_open,session_sf_pid,0);if(display<0){close(descriptor);die("private session SurfaceFlinger pidfd");}
                printf("PRIVATE_SYSTEMSERVER_SESSION_UNLIMITED_PID=%d\n",server);
                struct pollfd alive[2]={{.fd=descriptor,.events=POLLIN},{.fd=display,.events=POLLIN}};while(poll(alive,2,-1)<0)if(errno!=EINTR)die("private session monitor");close(descriptor);close(display);
                puts("PRIVATE_SYSTEMSERVER_OR_DISPLAY_EXITED_ENDING_SESSION");
            }else puts("PRIVATE_SYSTEMSERVER_NOT_FOUND_ENDING_SESSION");
        }else {printf("PRIVATE_SYSTEMSERVER_STARTUP_OBSERVATION_SECONDS=%d\n",physical_display?80:20);sleep(physical_display?80:20);}
    }
    // Zygote makes its own process group; stop the exact child and let its parent reap it.
    kill(zygote_pid,SIGKILL);while(waitpid(supervisor,&status,0)<0)if(errno!=EINTR)die("zygote reap");
    puts(start_system_server?"PRIVATE_ZYGOTE_STOPPED_SYSTEMSERVER_BOOT_UNPROVEN":"PRIVATE_ZYGOTE_STOPPED_NO_SYSTEM_SERVER_STARTED");return result;
}
static void cleanup_private_children(void){
    struct stat root_info;if(stat("/",&root_info))die("private root identity");DIR *proc=opendir("/proc");if(!proc)die("private children list");struct dirent *entry;
    while((entry=readdir(proc))){int pid=atoi(entry->d_name);if(pid<=1||pid==getpid())continue;char path[128];struct stat info;snprintf(path,sizeof(path),"/proc/%d/root",pid);
        if(!stat(path,&info)&&info.st_dev==root_info.st_dev&&info.st_ino==root_info.st_ino){printf("STOPPING_PRIVATE_ROOT_PROCESS=%d\n",pid);kill(pid,SIGKILL);}}
    closedir(proc);for(int retry=0;retry<20;retry++){int status;pid_t pid=waitpid(-1,&status,WNOHANG);if(pid<0&&errno==ECHILD)break;if(pid==0)usleep(100000);}
}
static int probe_isolated_services(int systemserver){
    if(systemserver){
        // Check the real UID/domain before leasing the screen. Watch only:
        // no input events are read and no EVIOCGRAB is issued.
        pid_t input_check=fork();if(input_check<0)die("input access preflight fork");
        if(!input_check){
            int context=open("/proc/self/attr/current",O_WRONLY|O_CLOEXEC);if(context<0)_exit(31);
            if(setgid(1000)||setuid(1000))_exit(32);
            const char *domain="u:r:system_server:s0";size_t length=strlen(domain);
            if(write(context,domain,length)!=(ssize_t)length)_exit(33);close(context);
            DIR *apex_directory=opendir("/apex");if(!apex_directory)_exit(40);
            unsigned apex_modules=0;struct dirent *module;
            while((module=readdir(apex_directory)))if(!strncmp(module->d_name,"com.",4)){
                if(!strcmp(module->d_name,"com.android.vndk.v33")&&!access("/apex/com.android.vndk.v33/.tempgsi-library-lists-only",R_OK))continue;
                apex_modules++;
            }
            closedir(apex_directory);if(apex_modules!=36)_exit(41);
            int permission_xml=open("/apex/com.android.permission/etc/permissions/com.android.permissioncontroller.xml",O_RDONLY|O_CLOEXEC);
            if(permission_xml<0)_exit(42);char xml_byte;if(read(permission_xml,&xml_byte,1)!=1)_exit(43);close(permission_xml);
            int watch=inotify_init1(IN_CLOEXEC|IN_NONBLOCK);if(watch<0)_exit(34);
            if(inotify_add_watch(watch,"/dev",IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO)<0)_exit(35);
            if(inotify_add_watch(watch,"/dev/input",IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO)<0)_exit(36);
            close(watch);
            const char *stats="/data/misc/apexdata/com.android.tethering/netstats";
            if(mkdir(stats,0700)&&errno!=EEXIST)_exit(37);
            const char *check="/data/misc/apexdata/com.android.tethering/netstats/.boot-access-check";
            int writable=open(check,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(writable<0)_exit(38);
            if(write(writable,"1",1)!=1||close(writable)||unlink(check))_exit(39);_exit(0);
        }
        int checked;while(waitpid(input_check,&checked,0)<0)if(errno!=EINTR)die("input access preflight reap");
        int result=WIFEXITED(checked)?WEXITSTATUS(checked):128+WTERMSIG(checked);
        printf("PRIVATE_INPUT_UID_1000_SYSTEM_SERVER_INOTIFY_PREFLIGHT=%d\n",result);if(result)return result;
        puts("PRIVATE_APEX_TETHERING_SYSTEM_SERVER_WRITE_PREFLIGHT_OK");
        puts("PRIVATE_APEX_ENUMERATION_AND_PERMISSION_XML_SYSTEM_SERVER_READ_OK");
    }
    struct stat host,isolated;if(stat("/dev/binder",&host))die("host binder identity");
    if(mkdir("/dev/binderfs",0755)||mount("binder","/dev/binderfs","binder",MS_NOSUID,"max=8"))die("private binderfs");
    int control=open("/dev/binderfs/binder-control",O_RDONLY|O_CLOEXEC);if(control<0)die("binder control");
    struct binderfs_device device={0};strcpy(device.name,"binder");
    if(access("/dev/binderfs/binder",F_OK)&&ioctl(control,BINDER_CTL_ADD,&device))die("create private binder");close(control);
    if(stat("/dev/binderfs/binder",&isolated))die("private binder identity");
    if(isolated.st_rdev==host.st_rdev)die("binder isolation identity collision");
    if(chmod("/dev/binderfs/binder",0666)||umount("/dev/binder")||mount("/dev/binderfs/binder","/dev/binder",NULL,MS_BIND,NULL))die("switch private binder only");
    printf("PRIVATE_BINDER_DEVICE_CREATED host=%u:%u private=%u:%u\n",major(host.st_rdev),minor(host.st_rdev),major(isolated.st_rdev),minor(isolated.st_rdev));
    int notice[2];if(pipe2(notice,O_CLOEXEC))die("service PID pipe");
    pid_t supervisor=fork();if(supervisor<0)die("service supervisor");
    if(!supervisor){close(notice[0]);child_notice=notice[1];
        if(systemserver){child_exec_context="u:r:servicemanager:s0";char *args[]={"/system/bin/servicemanager",NULL};_exit(child(args));}
        char *args[]={"/system/bin/sh","-c","export LD_PRELOAD=/data/local/tmp/private-selinux-mount.so; exec /system/bin/servicemanager",NULL};_exit(child(args));}
    close(notice[1]);pid_t service_pid;
    if(read(notice[0],&service_pid,sizeof(service_pid))!=sizeof(service_pid)||service_pid<=1)die("service PID receive");close(notice[0]);
    usleep(300000);
    char context_path[128],service_context[128]={0};snprintf(context_path,sizeof(context_path),"/proc/%d/attr/current",service_pid);
    FILE *context_input=fopen(context_path,"r");if(context_input){fgets(service_context,sizeof(service_context),context_input);fclose(context_input);}
    printf("PRIVATE_SERVICEMANAGER_PID=%d_CONTEXT=%s\n",service_pid,service_context);
    if(systemserver&&strcmp(service_context,"u:r:servicemanager:s0")){kill(service_pid,SIGKILL);while(waitpid(supervisor,NULL,0)<0)if(errno!=EINTR)die("service domain reap");return 19;}
    char *args[]={"/system/bin/sh","-c","while read command name value; do [ \"$command\" = export ] || exit 2; export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/runtime-smoke.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin IsolatedBinderProbe",NULL};
    int result=child(args),status;
    if(access("/data/local/tmp/isolated-binder.ok",F_OK))result=16;
    if(!result&&systemserver){
        pid_t hardware_supervisor=-1,hardware_pid=-1,allocator_supervisor=-1,allocator_pid=-1,secaudio_supervisor=-1,secaudio_pid=-1,wifi_hal_supervisor=-1,wifi_hal_pid=-1,camera_provider_supervisor=-1,camera_provider_pid=-1;
        pid_t memory_supervisor=-1,memory_pid=-1;
        if(!access("/data/local/tmp/controller.apk",F_OK)){
            pid_t bridge_supervisor;start_private_native_service("/system/bin/env CLASSPATH=/data/local/tmp/runtime-smoke.jar /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art /system/bin GuestReturnBridge",&bridge_supervisor);
        }
        // Private hwbinder and private hwservicemanager for all HAL registrations
        int ctl=open("/dev/binderfs/binder-control",O_RDONLY|O_CLOEXEC);struct binderfs_device hardware={0};strcpy(hardware.name,"hwbinder");
        if(ctl<0||(access("/dev/binderfs/hwbinder",F_OK)&&ioctl(ctl,BINDER_CTL_ADD,&hardware)))die("private hwbinder create");close(ctl);
        if(chmod("/dev/binderfs/hwbinder",0666)||umount("/dev/hwbinder")||mount("/dev/binderfs/hwbinder","/dev/hwbinder",NULL,MS_BIND,NULL))die("private hwbinder bind");
        int hardware_notice[2];if(pipe2(hardware_notice,O_CLOEXEC))die("private HIDL manager PID pipe");
        hardware_supervisor=fork();if(hardware_supervisor<0)die("private HIDL manager supervisor");
        if(!hardware_supervisor){close(hardware_notice[0]);child_notice=hardware_notice[1];child_exec_context="u:r:hwservicemanager:s0";char *hardware_args[]={"/system/bin/hwservicemanager",NULL};_exit(child(hardware_args));}
        close(hardware_notice[1]);if(read(hardware_notice[0],&hardware_pid,sizeof(hardware_pid))!=sizeof(hardware_pid)||hardware_pid<=1)die("private HIDL manager PID receive");close(hardware_notice[0]);
        printf("PRIVATE_HWSERVICEMANAGER_PID=%d_NO_HOST_HWBINDER\n",hardware_pid);
        usleep(500000);
        if(wifi_takeover){
            memory_pid=start_private_native_service("/system/system_ext/bin/hw/android.hidl.allocator@1.0-service",&memory_supervisor);
            puts("PRIVATE_GSI_HIDL_ASHMEM_ALLOCATOR_STARTED_FOR_AUDIO_EFFECT_BUFFERS");
        }
        if(camera166){
            int ctl166=open("/dev/binderfs/binder-control",O_RDONLY|O_CLOEXEC);
            struct binderfs_device vnd166={0};strcpy(vnd166.name,"vndbinder");
            if(ctl166<0||(access("/dev/binderfs/vndbinder",F_OK)&&ioctl(ctl166,BINDER_CTL_ADD,&vnd166)))die("private vendor binder create");close(ctl166);
            if(chmod("/dev/binderfs/vndbinder",0666)||mount("/dev/binderfs/vndbinder","/dev/vndbinder",NULL,MS_BIND,NULL))die("private vendor binder bind");
            pid_t manager166;start_private_native_service("/vendor/bin/vndservicemanager",&manager166);
        }
        allocator_pid=start_private_native_service("/vendor/bin/hw/vendor.qti.hardware.display.allocator-service",&allocator_supervisor);
        int graphics_marker=open("/data/local/tmp/graphics-buffer.ok",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(graphics_marker<0||fchown(graphics_marker,1000,1000))die("graphics preflight marker");close(graphics_marker);
        char *buffer_args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/runtime-smoke.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin BufferSmoke",NULL};
        run_as_system=1;int graphics_result=child(buffer_args);run_as_system=0;
        printf("PRIVATE_GRALLOC_PREFLIGHT_RESULT=%d\n",graphics_result);
        struct stat graphics_info;if(graphics_result||stat("/data/local/tmp/graphics-buffer.ok",&graphics_info)||graphics_info.st_size!=1)return 21;
        char *log_api_args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/balanced198.jar:/data/local/tmp/runtime-smoke.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin BootLogOverlay --check-api",NULL};
        int log_api=child(log_api_args);printf("PRIVATE_PHONE_BOOT_LOG_API_RESULT=%d\n",log_api);if(log_api)return 23;
        // GPU rendering is shared safely; display composer stays on private hwbinder.
        if(chown("/data/system",1000,1000))die("system data owner");
        puts(physical_display?"PRIVATE_SYSTEMSERVER_DISPLAY_LEASE_PREPARATION_UID_1000":"PRIVATE_SYSTEMSERVER_ENTRY_TEST_UID_1000_NO_HOST_HAL_NO_DISPLAY_TAKEOVER");
        int apex_notice[2];if(pipe2(apex_notice,O_CLOEXEC))die("APEX PID pipe");
        pid_t apex_supervisor=fork();if(apex_supervisor<0)die("APEX supervisor");
        if(!apex_supervisor){
            close(apex_notice[0]);child_notice=apex_notice[1];
            char *catalog_args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/runtime-smoke.jar; export LD_PRELOAD=/data/local/tmp/private-selinux-mount.so; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin ReadOnlyApexCatalog",NULL};_exit(child(catalog_args));
        }
        close(apex_notice[1]);pid_t apex_pid;if(read(apex_notice[0],&apex_pid,sizeof(apex_pid))!=sizeof(apex_pid)||apex_pid<=1)die("APEX PID receive");close(apex_notice[0]);
        printf("PRIVATE_APEX_CATALOG_PID=%d\n",apex_pid);
        int catalog_ready=0;for(int retry=0;retry<50;retry++){if(!access("/data/local/tmp/apex-catalog.ready",F_OK)){catalog_ready=1;break;}usleep(100000);}
        if(!catalog_ready){puts("EVOX_APEX_CATALOG_NOT_READY_NO_DISPLAY_HANDOFF");return 18;}
        pid_t art_supervisor;pid_t art_pid=start_private_native_service("/apex/com.android.art/bin/artd",&art_supervisor);
        if(!access("/dev/block",F_OK)||errno!=ENOENT)die("private vold requires absent block device tree");
        pid_t storaged_supervisor;pid_t storaged_pid=start_private_native_service("/system/bin/storaged",&storaged_supervisor);
        pid_t vold_supervisor;pid_t vold_pid=start_private_native_service("/system/bin/vold --blkid_context=u:r:blkid:s0 --blkid_untrusted_context=u:r:blkid_untrusted:s0 --fsck_context=u:r:fsck:s0 --fsck_untrusted_context=u:r:fsck_untrusted:s0",&vold_supervisor);
        int vold_marker=open("/data/local/tmp/vold-checkpoint.ok",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(vold_marker<0||fchown(vold_marker,1000,1000))die("vold preflight marker");close(vold_marker);
        char *vold_args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/runtime-smoke.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin VoldSmoke",NULL};
        run_as_system=1;int vold_result=child(vold_args);run_as_system=0;
        printf("PRIVATE_VOLD_CHECKPOINT_PREFLIGHT_RESULT=%d\n",vold_result);
        struct stat vold_info;if(vold_result||stat("/data/local/tmp/vold-checkpoint.ok",&vold_info)||vold_info.st_size!=1)return 22;
        char *bpf_args[]={"/system/bin/bpfloader",NULL};
        boot_kmsg_fd=open("/data/local/tmp/platform-bpf-loader.log",O_CREAT|O_EXCL|O_WRONLY,0600);if(boot_kmsg_fd<0)die("private BPF loader log descriptor");
        deny_bpf=2;int bpf_result=child(bpf_args);deny_bpf=0;close(boot_kmsg_fd);boot_kmsg_fd=-1;
        FILE *bpf_log=fopen("/data/local/tmp/platform-bpf-loader.log","r");if(bpf_log){char line[1024];while(fgets(line,sizeof(line),bpf_log))printf("PRIVATE_BPF_LOADER_LOG %s",line);fclose(bpf_log);}
        printf("PRIVATE_BPF_PLATFORM_LOADER_RESULT=%d_EMPTY_PROGRAM_SET\n",bpf_result);if(bpf_result)return 25;
        pid_t netd_supervisor;pid_t netd_pid=start_private_native_service("/system/bin/netd",&netd_supervisor);
        int netd_marker=open("/data/local/tmp/netd-alive.ok",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(netd_marker<0||fchown(netd_marker,1000,1000))die("netd preflight marker");close(netd_marker);
        char *netd_args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/runtime-smoke.jar:$SYSTEMSERVERCLASSPATH:/apex/com.android.tethering/javalib/service-connectivity.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin NetdSmoke",NULL};
        run_as_system=1;int netd_result=child(netd_args);run_as_system=0;
        printf("PRIVATE_NETD_PREFLIGHT_RESULT=%d\n",netd_result);
        struct stat netd_info;if(netd_result||stat("/data/local/tmp/netd-alive.ok",&netd_info)||netd_info.st_size!=1)return 24;
        // AudioPolicy requests a wake lock during startup: publish private suspend first.
        pid_t suspend_supervisor;pid_t suspend_pid=start_private_native_service("/system/bin/hw/android.system.suspend-service",&suspend_supervisor);
        // Start Samsung audio AIDL HAL and standard audio HAL
        pid_t audio_hal_supervisor=-1,audio_hal_pid=-1,audio_supervisor=-1,audio_pid=-1;
        pid_t camera_supervisor;pid_t camera_pid=start_private_native_service("/system/bin/cameraserver",&camera_supervisor);
        if(mkdir("/data/misc/gatekeeper",0700)&&errno!=EEXIST)die("private gatekeeper directory");
        if(chown("/data/misc/gatekeeper",1000,1000))die("private gatekeeper data owner");
        // No host Gatekeeper/TEE transport or credential store is exposed.
        pid_t gatekeeper_supervisor=-1,gatekeeper_pid=-1;
        if(!gatekeeper169)gatekeeper_pid=start_private_native_service("/system/bin/gatekeeperd /data/misc/gatekeeper",&gatekeeper_supervisor);
        if(mkdir("/data/misc/keystore",0700)&&errno!=EEXIST)die("private keystore directory");
        pid_t keymint_supervisor;pid_t keymint_pid=start_private_native_service("/data/local/tmp/soft-keymintd",&keymint_supervisor);
        pid_t keystore_supervisor;pid_t keystore_pid=start_private_native_service("/system/bin/keystore2 /data/misc/keystore",&keystore_supervisor);
        char *crypto_args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/runtime-smoke.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin KeystoreSmoke",NULL};
        run_as_system=1;int crypto_result=child(crypto_args);run_as_system=0;
        printf("PRIVATE_KEYSTORE_CRYPTO_PREFLIGHT_RESULT=%d\n",crypto_result);if(crypto_result)return 29;
        pid_t lmkd_supervisor;pid_t lmkd_pid=start_private_native_service("/system/bin/lmkd",&lmkd_supervisor);
        pid_t lmkd_check=fork();if(lmkd_check<0)die("lmkd protocol check fork");
        if(!lmkd_check){
            if(setgid(1000)||setuid(1000))_exit(44);
            struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/dev/socket/lmkd");
            int fd=-1,connected=0;
            for(int retry=0;retry<40;retry++){fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if(fd<0)_exit(45);if(!connect(fd,(struct sockaddr*)&address,sizeof(address))){connected=1;break;}close(fd);usleep(100000);}
            if(!connected)_exit(46);struct timeval timeout={.tv_sec=2};if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)))_exit(47);
            uint32_t request[]={htonl(4),htonl(0),htonl(1000)},response[2];
            if(send(fd,request,sizeof(request),0)!=(ssize_t)sizeof(request)||recv(fd,response,sizeof(response),0)!=(ssize_t)sizeof(response)||ntohl(response[0])!=4||ntohl(response[1])!=0)_exit(48);
            close(fd);_exit(0);
        }
        int lmkd_status;while(waitpid(lmkd_check,&lmkd_status,0)<0)if(errno!=EINTR)die("lmkd protocol check reap");
        int lmkd_result=WIFEXITED(lmkd_status)?WEXITSTATUS(lmkd_status):128+WTERMSIG(lmkd_status);
        printf("PRIVATE_LMKD_REAL_KILLCOUNT_QUERY_UID_1000_RESULT=%d_NO_KILLS_ALLOWED\n",lmkd_result);if(lmkd_result)return 28;
        int audio_marker=open("/data/local/tmp/audio-policy.ok",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(audio_marker<0||fchown(audio_marker,1000,1000))die("audio policy preflight marker");close(audio_marker);
        // installd sees only the private Binder and tmpfs /data created above.
        const char *install_dirs[]={"/data/app","/data/app-private","/data/user","/data/user_de","/data/misc","/data/misc/user","/data/misc/installd","/data/misc/profiles","/data/misc/profiles/cur","/data/misc/profiles/ref","/data/resource-cache","/data/system_ce","/data/system_de","/data/data"};
        for(unsigned i=0;i<sizeof(install_dirs)/sizeof(install_dirs[0]);i++)if(mkdir(install_dirs[i],0755)&&errno!=EEXIST)die("private installd directory");
        int install_notice[2];if(pipe2(install_notice,O_CLOEXEC))die("installd PID pipe");
        pid_t install_supervisor=fork();if(install_supervisor<0)die("installd supervisor");
        if(!install_supervisor){close(install_notice[0]);child_notice=install_notice[1];char *install_args[]={"/system/bin/sh","-c","export ASEC_MOUNTPOINT=/mnt/asec; export LD_PRELOAD=/data/local/tmp/private-selinux-mount.so; exec /system/bin/installd",NULL};_exit(child(install_args));}
        close(install_notice[1]);pid_t install_pid;if(read(install_notice[0],&install_pid,sizeof(install_pid))!=sizeof(install_pid)||install_pid<=1)die("installd PID receive");close(install_notice[0]);
        printf("PRIVATE_INSTALLD_PID=%d\n",install_pid);
        int mem_notice[2];if(pipe2(mem_notice,O_CLOEXEC))die("memtrack PID pipe");
        pid_t mem_supervisor=fork();if(mem_supervisor<0)die("memtrack supervisor");
        if(!mem_supervisor){close(mem_notice[0]);child_notice=mem_notice[1];char *mem_args[]={"/vendor/bin/hw/vendor.qti.hardware.memtrack-service",NULL};int rc=child(mem_args);printf("PRIVATE_MEMTRACK_EXIT=%d\n",rc);_exit(rc);}
        close(mem_notice[1]);pid_t mem_pid;if(read(mem_notice[0],&mem_pid,sizeof(mem_pid))!=sizeof(mem_pid)||mem_pid<=1)die("memtrack PID receive");close(mem_notice[0]);
        printf("PRIVATE_MEMTRACK_PID=%d\n",mem_pid);
        int power_notice[2];if(pipe2(power_notice,O_CLOEXEC))die("power PID pipe");
        pid_t power_supervisor=fork();if(power_supervisor<0)die("power supervisor");
        if(!power_supervisor){close(power_notice[0]);child_notice=power_notice[1];run_as_system=1;char *power_args[]={"/vendor/bin/hw/android.hardware.power.samsung-service",NULL};int rc=child(power_args);printf("PRIVATE_POWER_EXIT=%d\n",rc);_exit(rc);}
        close(power_notice[1]);pid_t power_pid;if(read(power_notice[0],&power_pid,sizeof(power_pid))!=sizeof(power_pid)||power_pid<=1)die("power PID receive");close(power_notice[0]);
        printf("PRIVATE_POWER_PID=%d\n",power_pid);
        int light_notice[2];if(pipe2(light_notice,O_CLOEXEC))die("lights PID pipe");
        pid_t light_supervisor=fork();if(light_supervisor<0)die("lights supervisor");
        if(!light_supervisor){close(light_notice[0]);child_notice=light_notice[1];run_as_system=1;char *light_args[]={"/vendor/bin/hw/vendor.samsung.hardware.light-service",NULL};int rc=child(light_args);printf("PRIVATE_LIGHTS_EXIT=%d\n",rc);_exit(rc);}
        close(light_notice[1]);pid_t light_pid;if(read(light_notice[0],&light_pid,sizeof(light_pid))!=sizeof(light_pid)||light_pid<=1)die("lights PID receive");close(light_notice[0]);
        printf("PRIVATE_LIGHTS_PID=%d\n",light_pid);
        pid_t health_supervisor,sensors_supervisor;
        pid_t health_pid=start_private_native_service("/vendor/bin/hw/vendor.samsung.hardware.health-service",&health_supervisor);
        pid_t sensors_pid=start_private_native_service("/vendor/bin/hw/android.hardware.sensors-service.multihal",&sensors_supervisor);
        if(!physical_display){
            char *idmap_start[]={"/system/bin/setprop","ctl.start","idmap2d",NULL};printf("PRIVATE_IDMAP2D_REQUEST_RESULT=%d\n",child(idmap_start));
            usleep(500000);char *list[]={"/system/bin/service","list",NULL};child(list);
            // IHealth stable AIDL transaction 12 is the readonly getHealthInfo().
            char *health_read[]={"/system/bin/service","call","android.hardware.health.IHealth/default","12",NULL};
            printf("PRIVATE_HEALTH_READ_ONLY_RESULT=%d\n",child(health_read));
        }
        // Diagnostic SF launch has no host hwbinder. It cannot
        // acquire the active One UI composer client or take over the display.
        int sf_notice[2];if(pipe2(sf_notice,O_CLOEXEC))die("surfaceflinger PID pipe");
        pid_t sf_supervisor=fork();if(sf_supervisor<0)die("surfaceflinger supervisor");
        if(!sf_supervisor){
            close(sf_notice[0]);child_notice=sf_notice[1];
            if(physical_display){
                if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))die("SF private mounts");
                char descriptor[64];
                if(umount("/dev/hwbinder")||mount("/dev/display-hwbinder","/dev/hwbinder",NULL,MS_BIND,NULL)||umount("/dev/display-hwbinder"))die("SF host HIDL only");
                int info=open("/dev/__properties__/property_info",O_PATH|O_CLOEXEC);if(info<0)die("SF property labels");
                if(mount("tmpfs","/dev/__properties__","tmpfs",MS_NOSUID|MS_NODEV,"size=16m,mode=0755"))die("SF private properties");
                int target=open("/dev/__properties__/property_info",O_CREAT|O_WRONLY,0444);if(target<0)die("SF property target");close(target);
                snprintf(descriptor,sizeof(descriptor),"/proc/self/fd/%d",info);bind_readonly(descriptor,"/dev/__properties__/property_info");close(info);
                int notice_fd=child_notice;child_notice=-1;char *seed[]={"/data/local/tmp/property-seed","--display",NULL};int seeded=child(seed);child_notice=notice_fd;if(seeded)_exit(95);
                char *sf_args[]={"/system/bin/sh","-c","i=0; while [ ! -f /data/local/tmp/display-lease.go ]; do i=$((i+1)); [ $i -lt 300 ] || exit 96; sleep 0.1; done; exec /system/bin/surfaceflinger",NULL};int rc=child(sf_args);printf("PRIVATE_SURFACEFLINGER_EXIT=%d\n",rc);_exit(rc);
            }
            char *sf_args[]={"/system/bin/surfaceflinger",NULL};int rc=child(sf_args);printf("PRIVATE_SURFACEFLINGER_EXIT=%d\n",rc);_exit(rc);
        }
        close(sf_notice[1]);pid_t sf_pid;if(read(sf_notice[0],&sf_pid,sizeof(sf_pid))!=sizeof(sf_pid)||sf_pid<=1)die("surfaceflinger PID receive");close(sf_notice[0]);
        if(physical_display)session_sf_pid=sf_pid;
        if(physical_display&&umount("/dev/display-hwbinder"))die("hide display HIDL from framework");
        printf("PRIVATE_SURFACEFLINGER_PID=%d_%s\n",sf_pid,physical_display?"WAITING_FOR_EXTERNAL_DISPLAY_LEASE":"NO_HOST_COMPOSER");
        if(!wifi_takeover){
            int audio_ready=0;for(int i=0;i<300;i++){if(!access("/data/local/tmp/audio-handoff.ready",F_OK)){audio_ready=1;break;}usleep(100000);}
            if(!audio_ready)die("EvoX host audio release gate unavailable");
            secaudio_pid=start_private_native_service("/vendor/bin/hw/secaudiohalaidl",&secaudio_supervisor);
            audio_hal_pid=start_private_native_service("/vendor/bin/hw/android.hardware.audio.service_64",&audio_hal_supervisor);
            audio_pid=start_private_native_service("/system/bin/audioserver",&audio_supervisor);
        }
        pid_t bt_supervisor165=-1,bt_pid165=-1,bt_audio_supervisor165=-1,bt_audio_pid165=-1;
        if(bluetooth165){
            int ready=0;for(int n=0;n<300;n++){if(!access("/data/local/tmp/bluetooth-handoff165.ready",F_OK)){ready=1;break;}usleep(100000);}
            if(!ready)die("Bluetooth host ownership not released");
            const char *dirs[]={"/data/vendor/bluetooth","/data/vendor/ssrdump"};
            const char *labels[]={"u:object_r:vendor_bt_data_file:s0","u:object_r:vendor_ramdump_vendor_data_file:s0"};
            for(unsigned n=0;n<2;n++){
                if((mkdir(dirs[n],0770)&&errno!=EEXIST)||chown(dirs[n],1002,1002)||chmod(dirs[n],0770)||lsetxattr(dirs[n],"security.selinux",labels[n],strlen(labels[n])+1,0))die("Bluetooth private data metadata");
            }
            bt_audio_pid165=start_private_native_service("/system/bin/hw/android.hardware.bluetooth.audio-service-system",&bt_audio_supervisor165);
            bt_pid165=start_private_native_service("/vendor/bin/hw/android.hardware.bluetooth@1.1-service-qti",&bt_supervisor165);
            printf("PRIVATE_BLUETOOTH165_HAL_PID=%d_NO_HOST_BOND_DATABASE\n",bt_pid165);
        }
        if(camera166){
            int ready166=0;for(int n=0;n<300;n++){if(!access("/data/local/tmp/camera-handoff166.ready",F_OK)){ready166=1;break;}usleep(100000);}
            if(!ready166)die("camera host ownership not released");
            const char *dirs166[]={"/data/vendor/camera","/data/vendor/postprocess","/data/vendor/postprocess/eraw","/data/vendor/postprocess/native"};
            for(unsigned n=0;n<4;n++){
                const char *label166=n?"u:object_r:vendor_postprocess_data_file:s0":"u:object_r:vendor_camera_data_file:s0";
                if((mkdir(dirs166[n],0770)&&errno!=EEXIST)||chown(dirs166[n],1006,n?5050:1006)||chmod(dirs166[n],0770)||lsetxattr(dirs166[n],"security.selinux",label166,strlen(label166)+1,0))die("private camera data metadata");
            }
            if(fingerprint167){
                int released167=0;for(int n=0;n<300;n++){if(!access("/data/local/tmp/fingerprint-handoff167.ready",F_OK)){released167=1;break;}usleep(100000);}
                if(!released167)die("fingerprint167 host not released");
                const char *fpdirs167[]={"/data/vendor/biometrics","/data/vendor/misc","/data/vendor/misc/qti_fp","/data/vendor/misc/qti_fp/template","/data/vendor/fpSnrTest","/efs/biometrics","/efs/biometrics/meta"};
                for(unsigned n=0;n<7;n++)if((mkdir(fpdirs167[n],0770)&&errno!=EEXIST)||chown(fpdirs167[n],1000,1000)||chmod(fpdirs167[n],0770))die("fingerprint167 private data");
                const char *mapped170[]={"/data/vendor/biometrics/fp","/data/vendor/biometrics/fp/User_10000"};
                for(unsigned n=0;n<2;n++){
                    const char *label170="u:object_r:vendor_fingerprint_data_file:s0";
                    if((mkdir(mapped170[n],0700)&&errno!=EEXIST)||chown(mapped170[n],1000,1000)||chmod(mapped170[n],0700)||lsetxattr(mapped170[n],"security.selinux",label170,strlen(label170)+1,0))die("Fingerprint170 private group storage");
                }
                pid_t fingerprint_supervisor167;start_private_native_service("/data/local/tmp/camera-runtime166/lineage-fingerprint170",&fingerprint_supervisor167);
                puts("FINGERPRINT170_FRAMEWORK_BRIDGE_GUEST0_SECURE10000");
            }
            if(gatekeeper169){
                int released169=0;for(int n=0;n<300;n++){if(!access("/data/local/tmp/gatekeeper-handoff169.ready",F_OK)){released169=1;break;}usleep(100000);}
                if(!released169)die("Gatekeeper169 host not released");
                const char *data169="/data/vendor/gatekeeper",*label169="u:object_r:vendor_gatekeeper_data_file:s0";
                if((mkdir(data169,0770)&&errno!=EEXIST)||chown(data169,1000,1000)||chmod(data169,0770)||lsetxattr(data169,"security.selinux",label169,strlen(label169)+1,0))die("Gatekeeper169 private vendor data");
                label169="u:object_r:gatekeeper_data_file:s0";if(lsetxattr("/data/misc/gatekeeper","security.selinux",label169,strlen(label169)+1,0))die("Gatekeeper169 private daemon data");
                pid_t hal_supervisor169;start_private_native_service("/vendor/bin/hw/android.hardware.gatekeeper@1.0-service",&hal_supervisor169);
                int mapped169=0;for(int n=0;n<150;n++){int check169=open("/data/local/tmp/gatekeeper-mapped169.ready",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);char value169=0;if(check169>=0){if(read(check169,&value169,1)==1&&value169=='1')mapped169=1;close(check169);}if(mapped169)break;usleep(100000);}
                if(!mapped169)die("Gatekeeper169 refuses to expose an unmapped hardware HAL");
                puts("GATEKEEPER169_MAPPING_CONFIRMED_BEFORE_DAEMON_RELEASE");
                gatekeeper_pid=start_private_native_service("/system/bin/gatekeeperd /data/misc/gatekeeper",&gatekeeper_supervisor);
                usleep(500000);if(kill(gatekeeper_pid,0)&&errno==ESRCH)die("Gatekeeper169 daemon exited before framework release");
            }
            pid_t hyper_supervisor166;start_private_native_service("/vendor/bin/hw/vendor.samsung.hardware.hyper-service",&hyper_supervisor166);
            camera_provider_pid=start_private_native_service("/data/local/tmp/camera-runtime166/vendor.samsung.hardware.camera.provider-service_64",&camera_provider_supervisor);
            printf("CAMERA166_PROVIDER_PID=%d\n",camera_provider_pid);
        }
        pid_t wificond_supervisor=-1,wificond_pid=-1;
        pid_t swcodec_supervisor=-1,swcodec_pid=-1,extractor_supervisor=-1,extractor_pid=-1,media_supervisor=-1,media_pid=-1;
        if(wifi_takeover){
            int ready=0;for(int i=0;i<300;i++){if(!access("/data/local/tmp/wifi-handoff.ready",F_OK)&&!access("/data/local/tmp/audio-handoff.ready",F_OK)){ready=1;break;}usleep(100000);}
            if(!ready)die("physical Wi-Fi handoff was not confirmed");
            if(access("/data/local/tmp/audio-handoff.ready",F_OK))die("host audio ownership was not released");
            secaudio_pid=start_private_native_service("/vendor/bin/hw/secaudiohalaidl",&secaudio_supervisor);
            audio_hal_pid=start_private_native_service("/vendor/bin/hw/android.hardware.audio.service_64",&audio_hal_supervisor);
            audio_pid=start_private_native_service("/system/bin/audioserver",&audio_supervisor);
            puts("PRIVATE_AUDIO_SERVICES_STARTED_AFTER_HOST_AUDIO_STOP");
            swcodec_pid=start_private_native_service("/apex/com.android.media.swcodec/bin/mediaswcodec",&swcodec_supervisor);
            extractor_pid=start_private_native_service("/system/bin/mediaextractor",&extractor_supervisor);
            media_pid=start_private_native_service("/system/bin/mediaserver64",&media_supervisor);
            puts("PRIVATE_GSI_SOFTWARE_CODEC_EXTRACTOR_PLAYER_STARTED_PLAYBACK_UNVERIFIED");
            const char *dirs[]={"/data/vendor/wifi","/data/vendor/wifi/wpa","/data/vendor/wifi/wpa/sockets","/data/vendor/wifi/hostapd","/data/misc/wifi"};
            for(unsigned i=0;i<sizeof(dirs)/sizeof(dirs[0]);i++){if(mkdir(dirs[i],0770)&&errno!=EEXIST)die("private Wi-Fi directory");if(chown(dirs[i],1010,1010)||chmod(dirs[i],0770))die("private Wi-Fi directory owner");}
            wifi_hal_pid=start_private_native_service("/vendor/bin/hw/android.hardware.wifi@1.0-service",&wifi_hal_supervisor);
            wificond_pid=start_private_native_service("/system/bin/wificond",&wificond_supervisor);
            char *supplicant_args[]={"/system/bin/setprop","ctl.start","wpa_supplicant",NULL};if(child(supplicant_args))die("private init supplicant start");
            puts("PRIVATE_WIFI_HAL_WIFICOND_SUPPLICANT_STARTED_AFTER_RADIO_HANDOFF");
        }
        if(physical_display&&!wifi_takeover){
            swcodec_pid=start_private_native_service("/apex/com.android.media.swcodec/bin/mediaswcodec",&swcodec_supervisor);
            extractor_pid=start_private_native_service("/system/bin/mediaextractor",&extractor_supervisor);
            media_pid=start_private_native_service("/system/bin/mediaserver64",&media_supervisor);
            puts("EVOX155_SOFTWARE_CODEC_EXTRACTOR_PLAYER_STARTED");
        }
        pid_t logger_supervisor=-1;
        if(physical_display){
            int logger_notice[2];if(pipe2(logger_notice,O_CLOEXEC))die("phone boot logger PID pipe");
            logger_supervisor=fork();if(logger_supervisor<0)die("phone boot logger supervisor");
            if(!logger_supervisor){close(logger_notice[0]);child_notice=logger_notice[1];char *log_args[]={"/system/bin/sh","-c","while read command name value; do export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/balanced198.jar:/data/local/tmp/runtime-smoke.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin BootLogOverlay",NULL};int log_result=child(log_args);printf("PRIVATE_PHONE_BOOT_LOG_EXIT=%d\n",log_result);_exit(log_result);}
            close(logger_notice[1]);pid_t logger_pid;if(read(logger_notice[0],&logger_pid,sizeof(logger_pid))!=sizeof(logger_pid)||logger_pid<=1)die("phone boot logger PID receive");close(logger_notice[0]);
            printf("PRIVATE_PHONE_BOOT_LOG_PID=%d\n",logger_pid);
        }
        int entered=catalog_ready?probe_zygote(1):18;
        if(logger_supervisor>1){kill(logger_supervisor,SIGKILL);while(waitpid(logger_supervisor,NULL,0)<0)if(errno!=EINTR)die("phone logger supervisor reap");}
        kill(health_pid,SIGKILL);while(waitpid(health_supervisor,NULL,0)<0)if(errno!=EINTR)die("health reap");
        kill(sensors_pid,SIGKILL);while(waitpid(sensors_supervisor,NULL,0)<0)if(errno!=EINTR)die("sensors reap");
        kill(sf_pid,SIGKILL);while(waitpid(sf_supervisor,NULL,0)<0)if(errno!=EINTR)die("surfaceflinger reap");
        kill(light_pid,SIGKILL);while(waitpid(light_supervisor,NULL,0)<0)if(errno!=EINTR)die("lights reap");
        kill(power_pid,SIGKILL);while(waitpid(power_supervisor,NULL,0)<0)if(errno!=EINTR)die("power reap");
        kill(suspend_pid,SIGKILL);while(waitpid(suspend_supervisor,NULL,0)<0)if(errno!=EINTR)die("suspend reap");
        kill(mem_pid,SIGKILL);while(waitpid(mem_supervisor,NULL,0)<0)if(errno!=EINTR)die("memtrack reap");
        kill(install_pid,SIGKILL);while(waitpid(install_supervisor,NULL,0)<0)if(errno!=EINTR)die("installd reap");
        kill(apex_pid,SIGKILL);while(waitpid(apex_supervisor,NULL,0)<0)if(errno!=EINTR)die("APEX reap");
        kill(art_pid,SIGKILL);while(waitpid(art_supervisor,NULL,0)<0)if(errno!=EINTR)die("private ART service reap");
        kill(storaged_pid,SIGKILL);while(waitpid(storaged_supervisor,NULL,0)<0)if(errno!=EINTR)die("private storaged reap");
        kill(vold_pid,SIGKILL);while(waitpid(vold_supervisor,NULL,0)<0)if(errno!=EINTR)die("private vold reap");
        kill(netd_pid,SIGKILL);while(waitpid(netd_supervisor,NULL,0)<0)if(errno!=EINTR)die("private netd reap");
        if(bt_pid165>1){kill(bt_pid165,SIGKILL);while(waitpid(bt_supervisor165,NULL,0)<0)if(errno!=EINTR)die("Bluetooth supervisor reap");}
        if(bt_audio_pid165>1){kill(bt_audio_pid165,SIGKILL);while(waitpid(bt_audio_supervisor165,NULL,0)<0)if(errno!=EINTR)die("Bluetooth audio supervisor reap");}
        kill(camera_pid,SIGKILL);while(waitpid(camera_supervisor,NULL,0)<0)if(errno!=EINTR)die("private cameraserver reap");
        if(media_pid>1){kill(media_pid,SIGKILL);while(waitpid(media_supervisor,NULL,0)<0)if(errno!=EINTR)die("private media player reap");
        }
        if(extractor_pid>1){kill(extractor_pid,SIGKILL);while(waitpid(extractor_supervisor,NULL,0)<0)if(errno!=EINTR)die("private media extractor reap");}
        if(swcodec_pid>1){kill(swcodec_pid,SIGKILL);while(waitpid(swcodec_supervisor,NULL,0)<0)if(errno!=EINTR)die("private software codec reap");}
        kill(audio_pid,SIGKILL);while(waitpid(audio_supervisor,NULL,0)<0)if(errno!=EINTR)die("private audioserver reap");
        kill(audio_hal_pid,SIGKILL);while(waitpid(audio_hal_supervisor,NULL,0)<0)if(errno!=EINTR)die("private audio HAL reap");
        if(gatekeeper_pid>1){kill(gatekeeper_pid,SIGKILL);while(waitpid(gatekeeper_supervisor,NULL,0)<0)if(errno!=EINTR)die("private gatekeeper reap");}
        kill(lmkd_pid,SIGKILL);while(waitpid(lmkd_supervisor,NULL,0)<0)if(errno!=EINTR)die("private lmkd reap");
        kill(keystore_pid,SIGKILL);while(waitpid(keystore_supervisor,NULL,0)<0)if(errno!=EINTR)die("private keystore reap");
        kill(keymint_pid,SIGKILL);while(waitpid(keymint_supervisor,NULL,0)<0)if(errno!=EINTR)die("private software keymint reap");
        if(allocator_pid>1){kill(allocator_pid,SIGKILL);while(waitpid(allocator_supervisor,NULL,0)<0)if(errno!=EINTR)die("private graphics allocator reap");}
        if(memory_pid>1){kill(memory_pid,SIGKILL);while(waitpid(memory_supervisor,NULL,0)<0)if(errno!=EINTR)die("private HIDL memory allocator reap");}
        if(hardware_pid>1){kill(hardware_pid,SIGKILL);while(waitpid(hardware_supervisor,NULL,0)<0)if(errno!=EINTR)die("private HIDL manager reap");}
        if(secaudio_pid>1){kill(secaudio_pid,SIGKILL);while(waitpid(secaudio_supervisor,NULL,0)<0)if(errno!=EINTR)die("private secaudio reap");}
        if(wifi_hal_pid>1){kill(wifi_hal_pid,SIGKILL);while(waitpid(wifi_hal_supervisor,NULL,0)<0)if(errno!=EINTR)die("private wifi HAL reap");}
        if(wificond_pid>1){kill(wificond_pid,SIGKILL);while(waitpid(wificond_supervisor,NULL,0)<0)if(errno!=EINTR)die("private wificond reap");}
        if(camera_provider_pid>1){kill(camera_provider_pid,SIGKILL);while(waitpid(camera_provider_supervisor,NULL,0)<0)if(errno!=EINTR)die("private camera provider reap");}
        printf("PRIVATE_SYSTEMSERVER_ENTRY_PROCESS_RESULT=%d_GUI_READINESS_UNPROVEN\n",entered);
    }
    kill(service_pid,SIGKILL);while(waitpid(supervisor,&status,0)<0)if(errno!=EINTR)die("service reap");
    printf("PRIVATE_SERVICE_MANAGER_RESULT=%d\n",result);
    puts("PRIVATE_SERVICE_MANAGER_STOPPED_HOST_SERVICES_UNCHANGED");return result;
}
#include "../../common/host_guard.h"
int main(int argc,char **argv){
    if(require_dm1q_host())return 31;
    if(argc==2&&!strcmp(argv[1],"--check-host")){
        puts("DM1Q_HOST_MATCH_NO_CHANGES");return 0;
    }
    char path[512];int shell_result,sf_result,app_result,vm_result,jni_result,zygote_result;
    if((argc<3||argc>12) || strncmp(argv[1],"/dev/block/",11) || strcmp(argv[2],"/data/local/tmp/tempgsi-evox154/runtime"))return 2;
    physical_display=argc>=4&&!strcmp(argv[3],"--isolated-display-lease");
    int hardware_link_mode=argc==4&&!strcmp(argv[3],"--hardware-link-probe");
    int server_mode=physical_display||(argc>=4&&!strcmp(argv[3],"--isolated-systemserver"));
    int isolated_mode=argc>=4&&(!strcmp(argv[3],"--isolated-services")||server_mode);if(argc>=4&&!isolated_mode&&!hardware_link_mode)return 2;
    for(int i=5;i<argc;i++){
        if(physical_display&&!strcmp(argv[i],"--unlimited-session")&&!unlimited_session)unlimited_session=1;
        else if(physical_display&&!strcmp(argv[i],"--wifi-handoff")&&!wifi_takeover)wifi_takeover=1;
        else if(physical_display&&!strcmp(argv[i],"--radio-handoff")&&!radio_takeover139)radio_takeover139=1;
        else if(physical_display&&!strcmp(argv[i],"--bluetooth-handoff")&&!bluetooth165)bluetooth165=1;
        else if(physical_display&&!strcmp(argv[i],"--camera-handoff")&&!camera166)camera166=1;
        else if(physical_display&&!strcmp(argv[i],"--fingerprint-probe")&&!fingerprint167)fingerprint167=1;
        else if(physical_display&&!strcmp(argv[i],"--gatekeeper-handoff")&&!gatekeeper169)gatekeeper169=1;
        else return 2;
    }
    if(server_mode&&(argc<5||strncmp(argv[4],"/dev/block/",11)||!strcmp(argv[1],argv[4])))return 2;
    if(getuid()!=0)return 3;
    if(gatekeeper169&&!fingerprint167)return 2;
    if(fingerprint167&&!camera166)return 2;
    if(camera166&&(!bluetooth165||!physical_display||!wifi_takeover))return 2;
    if(bluetooth165){
        if(!physical_display||!wifi_takeover)return 2;
        bt_address165=open("/mnt/vendor/efs/bluetooth/bt_addr",O_PATH|O_CLOEXEC);
        struct stat info;
        if(bt_address165<0||fstat(bt_address165,&info)||!S_ISREG(info.st_mode)||info.st_size>64)die("Bluetooth address metadata");
    }
#ifdef TEMPGSI_HAL_PROFILE151
    {char firmware[PROP_VALUE_MAX];if(__system_property_get("ro.bootloader",firmware)<=0||strcmp(firmware,"S911BXXSAFZG1")){
        fputs("HAL_PROFILE151_FIRMWARE_MISMATCH_NO_MOUNTS_CHANGED\n",stderr);return 31;}}
#endif
    if(server_mode){
        char group[256],control[300],pid[32];snprintf(group,sizeof(group),"/sys/fs/cgroup/tempgsi_session_%d",getppid());
        if(getppid()<=1||mkdir(group,0755))die("exclusive guest session cgroup");
        snprintf(control,sizeof(control),"%s/cgroup.kill",group);if(access(control,W_OK))die("guest cgroup atomic termination unavailable");
        snprintf(control,sizeof(control),"%s/cgroup.procs",group);int fd=open(control,O_WRONLY|O_CLOEXEC);int length=snprintf(pid,sizeof(pid),"%d",getpid());
        if(fd<0||write(fd,pid,length)!=length)die("move loader to private session cgroup");close(fd);
        printf("PRIVATE_SESSION_CGROUP=%s\n",group);
    }
    cleanup_owner=getpid();if(atexit(cleanup_on_exit))die("cleanup registration");
    umask(0022);
    if(physical_display){
        const char *directory="/data/local/tmp/tempgsi-evox154/logs";
        if(mkdir(directory,0700)&&errno!=EEXIST)die("persistent phone boot log directory");
        snprintf(phone_log_source,sizeof(phone_log_source),"%s/boot-%lld-%d.log",directory,(long long)time(NULL),getpid());
        int log=open(phone_log_source,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);if(log<0)die("persistent phone boot log");
        dprintf(log,"GSI private userspace session. Full screen logs start after private SurfaceFlinger is ready.\n");close(log);
        printf("PHONE_BOOT_LOG_HOST_PATH=%s\n",phone_log_source);
    }
    if(server_mode){
        secure_private_config("/data/local/tmp/tempgsi-private-selinux.so","u:object_r:system_file:s0");
        secure_private_config("/data/local/tmp/tempgsi-gsionlocked198/ld.config166.txt","u:object_r:linkerconfig_file:s0");
        secure_private_config("/data/local/tmp/tempgsi-lineage-file-contexts.compat","u:object_r:file_contexts_file:s0");
        secure_private_config("/data/local/tmp/tempgsi-lineage-service-contexts.compat","u:object_r:service_contexts_file:s0");
        if(!access("/data/local/tmp/tempgsi-control.apk",F_OK))secure_private_config("/data/local/tmp/tempgsi-control.apk","u:object_r:system_file:s0");
    }
    if(prctl(PR_SET_CHILD_SUBREAPER,1))die("private child reaping");
    setbuf(stdout,NULL);alarm(physical_display?(unlimited_session?0:180):90);
    struct stat original_netns,private_netns;
    if(server_mode&&stat("/proc/self/ns/net",&original_netns))die("original network namespace identity");
    if(unshare(CLONE_NEWNS))die("unshare mount namespace");
    if(server_mode){
        if(unshare(CLONE_NEWNET)||stat("/proc/self/ns/net",&private_netns))die("private network namespace");
        if(original_netns.st_dev==private_netns.st_dev&&original_netns.st_ino==private_netns.st_ino)die("refuse shared network namespace");
    }
    if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))die("private mounts");
    if(mount(argv[1],base,"ext4",MS_RDONLY|MS_NOSUID|MS_NODEV,"noload"))die("mount readonly GSI");
    if(camera166){
        subpath(path,"/efs");struct stat efs166;if(stat(path,&efs166)||!S_ISDIR(efs166.st_mode))die("camera private efs mountpoint");
        if(mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=64k,mode=0755"))die("camera private calibration tree");
    }
    subpath(path,"/system/framework/services.jar");bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/services-face172.jar",path);
    subpath(path,"/system/product/etc/permissions/privapp-permissions-google-p.xml");bind_readonly("/data/local/tmp/tempgsi-evox154/privapp-google-p.xml",path);
    subpath(path,"/data");if(mount(server_mode?argv[4]:"tmpfs",path,server_mode?"ext4":"tmpfs",MS_NOSUID|MS_NODEV,server_mode?"user_xattr":"size=128m,mode=0755"))die("private data");
    if(physical_display&&module_overlay146(base))die("private guest file modules146 overlay");
    subpath(path,"/apex");if(mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV,"size=16m,mode=0755"))die("private apex");
    inherit_private_directory_label("/apex");
    if(server_mode){subpath(path,"/data_mirror");if(mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=4m,mode=0700,uid=0,gid=1000"))die("private data mirror tmpfs");inherit_private_directory_label("/data_mirror");}
    subpath(path,"/apex/com.android.runtime");if(mkdir(path,0755))die("runtime directory");
    bind_readonly(argv[2],path);
    {
        DIR *dir=opendir("/data/local/tmp/tempgsi-evox154/apex");struct dirent *entry;
        if(!dir)die("apex cache");
        while((entry=readdir(dir))){
            char source[512],suffix[128];struct stat info;
            if(strncmp(entry->d_name,"com.",4)||strlen(entry->d_name)>90)continue;
            snprintf(source,sizeof(source),"/data/local/tmp/tempgsi-evox154/apex/%s",entry->d_name);
            if(stat(source,&info))continue;
            if(!S_ISDIR(info.st_mode))continue;
            snprintf(suffix,sizeof(suffix),"/apex/%.90s",entry->d_name);subpath(path,suffix);
            if(mkdir(path,0755))die("apex directory");bind_readonly(source,path);
        }
        closedir(dir);
    }
    puts("EVOX156_ORIGINAL_ANDROID16_CONNECTIVITY_AND_TELEPHONY_PRESERVED");
    if(server_mode){
        // Vendor Java apps read these versioned lists even though this GSI no
        // longer ships the VNDK 33 APEX. Expose the real firmware lists read-only;
        // this is metadata compatibility, not activation of an extra APEX.
        const char *lists[]={"llndk.libraries.33.txt","vndksp.libraries.33.txt"};
        const char *compat="/apex/com.android.vndk.v33";
        for(unsigned i=0;i<2;i++){
            char source[256];snprintf(source,sizeof(source),"%s/etc/%s",compat,lists[i]);
            if(access(source,R_OK))die("original VNDK 33 library list missing");
        }
        subpath(path,compat);if(mkdir(path,0755))die("private legacy library metadata directory");
        subpath(path,"/apex/com.android.vndk.v33/etc");if(mkdir(path,0755))die("private legacy library list directory");
        for(unsigned i=0;i<2;i++){
            char source[256];snprintf(source,sizeof(source),"%s/etc/%s",compat,lists[i]);subpath(path,source);
            int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0444);if(fd<0)die("private legacy library list target");close(fd);
            bind_readonly(source,path);
        }
        subpath(path,"/apex/com.android.vndk.v33/.tempgsi-library-lists-only");
        int marker=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0444);if(marker<0)die("private legacy library metadata marker");close(marker);
        puts("PRIVATE_ORIGINAL_VNDK33_LIBRARY_LISTS_READONLY_NOT_AN_ACTIVATED_APEX");
    }
    subpath(path,"/proc");
    if(server_mode){
        if(mount("proc",path,"proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))die("private proc mount");
        const char *protected[]={"/proc/sys","/proc/sysrq-trigger","/proc/irq","/proc/bus","/proc/fs"};
        for(unsigned i=0;i<sizeof(protected)/sizeof(protected[0]);i++){
            subpath(path,protected[i]);if(!access(path,F_OK))bind_readonly(path,path);
        }
        if(wifi_takeover){
            // IpClient/netd configure IPv6 before DHCP. Keep global sysctls
            // protected, but allow interface settings owned by this verified
            // separate network namespace (including interfaces added later).
            const char *conf[]={"/proc/sys/net/ipv4/conf","/proc/sys/net/ipv6/conf"};
            for(unsigned i=0;i<sizeof(conf)/sizeof(conf[0]);i++){
                subpath(path,conf[i]);
                if(mount(path,path,NULL,MS_BIND,NULL)||mount(NULL,path,NULL,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))die("private interface sysctl writable exception");
            }
            puts("PRIVATE_NETNS_IPV4_IPV6_INTERFACE_SYSCTLS_WRITABLE_GLOBAL_SYSCTLS_READONLY");
        }
    }else bind_readonly("/proc",path);
    subpath(path,"/sys");
    if(physical_display){
        // sysfs captures a network namespace when mounted. A host bind exposes
        // the host's /sys/class/net, hiding a PHY moved into the guest.
        if(mount("sysfs",path,"sysfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))die("guest network namespace sysfs");
        // AGM opens this status node O_RDWR, even for reads. Give only this
        // exact file its own mount before making the parent sysfs read-only.
        subpath(path,"/sys/kernel/snd_card/card_state");
        if(mount(path,path,NULL,MS_BIND,NULL))die("private AGM sound card status mount");
        if(bluetooth165){
            const char *nodes[]={"/sys/class/rfkill/rfkill0/state","/sys/power/wake_lock","/sys/power/wake_unlock"};
            for(unsigned n=0;n<3;n++){subpath(path,nodes[n]);if(mount(path,path,NULL,MS_BIND,NULL))die("Bluetooth exact sysfs exception");}
        }
        subpath(path,"/sys");
        if(mount(NULL,path,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))die("readonly private sysfs parent");
        subpath(path,"/sys/kernel/snd_card/card_state");
        int state_fd=open(path,O_RDWR|O_CLOEXEC);
        if(state_fd<0)die("private AGM status O_RDWR preflight");
        close(state_fd);
        puts("PRIVATE_AGM_EXACT_STATUS_NODE_RDWR_PREFLIGHT_PASSED_SYSFS_PARENT_READONLY");
    }else bind_readonly("/sys",path);
    if(server_mode){
        struct stat host_bpf,guest_bpf;if(stat("/sys/fs/bpf",&host_bpf))die("host BPF identity");
        subpath(path,"/sys/fs/bpf");if(mount("bpf",path,"bpf",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))die("private independent BPF filesystem");
        if(stat(path,&guest_bpf)||(host_bpf.st_dev==guest_bpf.st_dev&&host_bpf.st_ino==guest_bpf.st_ino))die("refuse shared BPF filesystem");
        puts("PRIVATE_BPF_FILESYSTEM_IDENTITY_DIFFERS_FROM_HOST");
        const char *program_dirs[]={"/system/etc/bpf","/vendor/etc/bpf","/apex/com.android.tethering/etc/bpf"};
        for(unsigned i=0;i<sizeof(program_dirs)/sizeof(program_dirs[0]);i++){subpath(path,program_dirs[i]);if(!access(path,F_OK)&&mount("tmpfs",path,"tmpfs",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=1m,mode=0755"))die("isolated legacy empty BPF program configuration");}
    }
    subpath(path,"/sys/fs/selinux");bind_readonly("/sys/fs/selinux",path);
    // SELinux access/context nodes are query interfaces. Policy/enforce remain readonly.
    subpath(path,"/sys/fs/selinux/access");if(mount("/sys/fs/selinux/access",path,NULL,MS_BIND,NULL))die("SELinux access query bind");
    subpath(path,"/sys/fs/selinux/context");if(mount("/sys/fs/selinux/context",path,NULL,MS_BIND,NULL))die("SELinux context query bind");
    subpath(path,"/vendor");bind_readonly("/vendor",path);
    if(server_mode){subpath(path,"/vendor/etc/vintf");bind_readonly(radio_takeover139?(bluetooth165?"/data/local/tmp/tempgsi-gsionlocked198/vintf":"/data/local/tmp/tempgsi-evox154/vendor-vintf-radio139"):wifi_takeover?"/data/local/tmp/tempgsi-evox154/vendor-vintf-wifi122":"/data/local/tmp/tempgsi-evox154/vendor-vintf-compat",path);}
    subpath(path,"/odm");bind_readonly("/odm",path);
    if(server_mode){subpath(path,"/system/etc/selinux/plat_file_contexts");bind_readonly("/data/local/tmp/tempgsi-lineage-file-contexts.compat",path);}
    if(server_mode){subpath(path,"/system/etc/selinux/plat_service_contexts");bind_readonly("/data/local/tmp/tempgsi-lineage-service-contexts.compat",path);}
    // App domains must exist in the policy running in Samsung's shared kernel.
    // Use its actual app mapping only in this guest mount namespace.
    if(server_mode){subpath(path,"/system/etc/selinux/plat_seapp_contexts");bind_readonly("/system/etc/selinux/plat_seapp_contexts",path);}
    subpath(path,"/dev");if(mount("tmpfs",path,"tmpfs",MS_NOSUID,"size=1m,mode=0755"))die("private dev");
    inherit_private_directory_label("/dev");
    if(server_mode){subpath(path,"/dev/input");if(mkdir(path,0755)||mount("/dev/input",path,NULL,MS_BIND,NULL)||mount(NULL,path,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID,NULL))die("physical session input devices");}
    if(server_mode&&!access("/dev/dma_heap",F_OK)){subpath(path,"/dev/dma_heap");if(mkdir(path,0755)||mount("/dev/dma_heap",path,NULL,MS_BIND,NULL)||mount(NULL,path,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID,NULL))die("private graphics DMA allocation devices");}
    if(bluetooth165){
        const char *nodes[]={"/dev/btpower","/dev/ttyHS0"};
        const unsigned majors[]={0x1d8,0x1ef};
        for(unsigned n=0;n<2;n++){
            struct stat original,exposed;
            if(stat(nodes[n],&original)||!S_ISCHR(original.st_mode)||major(original.st_rdev)!=majors[n]||minor(original.st_rdev)!=0)die("Bluetooth host device identity");
            subpath(path,nodes[n]);int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
            if(fd<0)die("Bluetooth device target");close(fd);
            if(mount(nodes[n],path,NULL,MS_BIND,NULL)||stat(path,&exposed)||exposed.st_rdev!=original.st_rdev||!S_ISCHR(exposed.st_mode))die("Bluetooth exact device bind");
        }
    }
    if(fingerprint167){
        const char *nodes167[]={"/dev/qbt2000_fd","/dev/qbt2000_ipc","/dev/smcinvoke"};
        const unsigned majors167[]={0x1e6,0x1e6,0x1df},minors167[]={0,1,0};
        for(unsigned n=0;n<3;n++){
            struct stat original167,exposed167;if(stat(nodes167[n],&original167)||!S_ISCHR(original167.st_mode)||major(original167.st_rdev)!=majors167[n]||minor(original167.st_rdev)!=minors167[n])die("fingerprint167 host identity");
            subpath(path,nodes167[n]);int fd167=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd167<0)die("fingerprint167 device target");close(fd167);
            if(mount(nodes167[n],path,NULL,MS_BIND,NULL)||stat(path,&exposed167)||!S_ISCHR(exposed167.st_mode)||exposed167.st_rdev!=original167.st_rdev)die("fingerprint167 exact char bind");
        }
    }
    if(camera166){
        const char *devices166[]={"/dev/adsprpc-smd","/dev/cvp","/dev/synx_device"};
        const unsigned majors166[]={0x1e8,0x1dd,0x1f3};
        for(unsigned n=0;n<3;n++){
            struct stat original166,exposed166;
            if(stat(devices166[n],&original166)||!S_ISCHR(original166.st_mode)||major(original166.st_rdev)!=majors166[n]||minor(original166.st_rdev)!=0)die("camera accelerator host identity");
            subpath(path,devices166[n]);int fd166=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd166<0)die("camera accelerator target");close(fd166);
            if(mount(devices166[n],path,NULL,MS_BIND,NULL)||stat(path,&exposed166)||exposed166.st_rdev!=original166.st_rdev||!S_ISCHR(exposed166.st_mode))die("camera accelerator exact bind");
        }
    }
    subpath(path,"/dev/null");if(mknod(path,S_IFCHR|0666,makedev(1,3)))die("null");
    if(server_mode){
        struct stat fuse;if(stat("/dev/fuse",&fuse)||!S_ISCHR(fuse.st_mode))die("host FUSE device identity");
        subpath(path,"/dev/fuse");if(mknod(path,S_IFCHR|0666,fuse.st_rdev)||chmod(path,0666))die("private FUSE device node");
    }
    subpath(path,"/dev/urandom");if(mknod(path,S_IFCHR|0666,makedev(1,9)))die("urandom");
    if(wifi_takeover){
        subpath(path,"/dev/wlan");int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(fd<0)die("Wi-Fi driver control target");close(fd);
        if(mount("/dev/wlan",path,NULL,MS_BIND,NULL))die("leased Wi-Fi driver control device");
    }
    {const char *nodes[]={"/dev/null","/dev/urandom"};
    for(unsigned i=0;i<2;i++){char label[1024];ssize_t size=getxattr(nodes[i],"security.selinux",label,sizeof(label));if(size<=0)die("host device label");subpath(path,nodes[i]);if(chmod(path,0666)||lsetxattr(path,"security.selinux",label,size,0))die("private device permission/label");}}
    if(!access("/dev/ashmem",F_OK)){
        subpath(path,"/dev/ashmem");int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("ashmem target");close(fd);if(mount("/dev/ashmem",path,NULL,MS_BIND,NULL))die("ashmem bind");
        char boot_id[64],suffix[128];FILE *input=fopen("/proc/sys/kernel/random/boot_id","r");
        if(!input||!fgets(boot_id,sizeof(boot_id),input))die("ashmem boot identity");fclose(input);boot_id[strcspn(boot_id,"\r\n")]=0;
        if(strlen(boot_id)!=36||strspn(boot_id,"0123456789abcdef-")!=36)die("invalid boot identity");
        snprintf(suffix,sizeof(suffix),"/dev/ashmem%s",boot_id);subpath(path,suffix);
        fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("ashmem libcutils target");close(fd);
        if(mount(suffix,path,NULL,MS_BIND,NULL))die("ashmem libcutils device bind");
    }
    if(!access("/dev/kmsg",F_OK)){
        subpath(path,"/dev/kmsg");int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("kernel log target");close(fd);if(mount("/dev/kmsg",path,NULL,MS_BIND,NULL))die("kernel log bind");
    }
    subpath(path,"/dev/binder");{int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("binder target");close(fd);if(mount("/dev/binder",path,NULL,MS_BIND,NULL))die("binder bind");}
    if(camera166){subpath(path,"/dev/vndbinder");int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd<0)die("private vendor binder target");close(fd);}
    subpath(path,"/dev/hwbinder");{int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("hwbinder target");close(fd);if(mount("/dev/hwbinder",path,NULL,MS_BIND,NULL))die("hwbinder bind");}
    if(physical_display){subpath(path,"/dev/display-hwbinder");int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("display HIDL target");close(fd);if(mount("/dev/hwbinder",path,NULL,MS_BIND,NULL))die("display HIDL bind");}
    if(!access("/dev/kgsl-3d0",F_OK)){
        subpath(path,"/dev/kgsl-3d0");int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("GPU target");close(fd);if(mount("/dev/kgsl-3d0",path,NULL,MS_BIND,NULL))die("GPU bind");
    }
    if(!access("/dev/snd",F_OK)){
        subpath(path,"/dev/snd");if(mkdir(path,0755)||mount("/dev/snd",path,NULL,MS_BIND,NULL))die("audio ALSA devices bind");
    }
    {
        const char *audio_nodes[]={"/dev/msm_audio_ion","/dev/msm_audio_ion_cma"};
        for(unsigned i=0;i<sizeof(audio_nodes)/sizeof(audio_nodes[0]);i++){
            if(!access(audio_nodes[i],F_OK)){
                subpath(path,audio_nodes[i]);int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd>=0){close(fd);mount(audio_nodes[i],path,NULL,MS_BIND,NULL);}
            }
        }
    }
    if(physical_display){
        // Kalama AGM talks to ADSP through this driver, not just ALSA /dev/snd.
        // Without it GPR init fails and AudioService waits on AGM indefinitely.
        const char *node="/dev/aud_pasthru_adsp";
        struct stat original,exposed;
        if(stat(node,&original)||!S_ISCHR(original.st_mode))die("original ADSP audio transport device");
        subpath(path,node);int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(fd<0)die("private ADSP audio transport target");close(fd);
        if(mount(node,path,NULL,MS_BIND,NULL)||stat(path,&exposed)||!S_ISCHR(exposed.st_mode)||original.st_rdev!=exposed.st_rdev)die("private ADSP audio transport bind identity");
        puts("PRIVATE_ADSP_AUDIO_TRANSPORT_EXACT_DEVICE_BOUND");
    }
    {
        DIR *dev_dir=opendir("/dev");
        if(dev_dir){
            struct dirent *de;
            while((de=readdir(dev_dir))){
                if(!strncmp(de->d_name,"video",5)||!strncmp(de->d_name,"media",5)||(camera166&&!strncmp(de->d_name,"v4l-subdev",10))){
                    char host_dev[64];snprintf(host_dev,sizeof(host_dev),"/dev/%s",de->d_name);
                    struct stat original166,exposed166;
                    if(stat(host_dev,&original166)||!S_ISCHR(original166.st_mode))die("camera host char identity");
                    subpath(path,host_dev);int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd<0)die("camera char target");close(fd);
                    if(mount(host_dev,path,NULL,MS_BIND,NULL)||stat(path,&exposed166)||!S_ISCHR(exposed166.st_mode)||original166.st_rdev!=exposed166.st_rdev)die("camera exact char bind");
                }
            }
            closedir(dev_dir);
        }
    }
    {
        const char *modem_nodes[]={"/dev/ipa","/dev/rmnet_ctrl","/dev/smdcntl8"};
        for(unsigned i=0;i<sizeof(modem_nodes)/sizeof(modem_nodes[0]);i++){
            if(!access(modem_nodes[i],F_OK)){
                subpath(path,modem_nodes[i]);int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd>=0){close(fd);mount(modem_nodes[i],path,NULL,MS_BIND,NULL);}
            }
        }
    }
    subpath(path,"/dev/__properties__");if(mkdir(path,0755))die("properties directory");
    if(mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV,"size=16m,mode=0755"))die("private properties");
    inherit_private_directory_label("/dev/__properties__");
    subpath(path,"/dev/__properties__/property_info");{int fd=open(path,O_CREAT|O_WRONLY,0444);if(fd<0)die("property info target");close(fd);}
    bind_readonly("/dev/__properties__/property_info",path);
    if(!access("/dev/socket/logdw",F_OK)){
        subpath(path,"/dev/socket");if(mkdir(path,0755))die("private log directory");
        inherit_private_directory_label("/dev/socket");
        subpath(path,"/dev/socket/logdw");{int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("log socket target");close(fd);}
        bind_readonly("/dev/socket/logdw",path);
    }
    if(server_mode&&!access("/dev/socket/tombstoned_java_trace",F_OK)){
        subpath(path,"/dev/socket/tombstoned_java_trace");int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("Java trace socket target");close(fd);
        bind_readonly("/dev/socket/tombstoned_java_trace",path);
    }
    if(physical_display){subpath(path,"/dev/socket/logdr");int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("phone log reader socket target");close(fd);bind_readonly("/dev/socket/logdr",path);}
    {
        const char *sys_socks[]={"/dev/socket/audioserver","/dev/socket/qmux_radio","/dev/socket/netmgr","/dev/socket/imsd","/dev/socket/wifihal"};
        for(unsigned i=0;i<sizeof(sys_socks)/sizeof(sys_socks[0]);i++){
            if(!access(sys_socks[i],F_OK)){
                struct stat st;if(!stat(sys_socks[i],&st)){
                    subpath(path,sys_socks[i]);
                    if(S_ISDIR(st.st_mode)){mkdir(path,0755);mount(sys_socks[i],path,NULL,MS_BIND,NULL);}
                    else{int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd>=0){close(fd);bind_readonly(sys_socks[i],path);}}
                }
            }
        }
    }
    if(server_mode){
        // This is the guest's ext4 /data, never a bind of host /data/adb.
        // Module storage must exist independently even when no Zygisk runtime
        // has been integrated yet. Do not run host ksud service hooks here.
        const char *directories[]={"/data/adb","/data/adb/modules","/data/adb/modules_update","/data/adb/tempgsi"};
        for(unsigned i=0;i<sizeof(directories)/sizeof(directories[0]);i++){
            subpath(path,directories[i]);if(mkdir(path,0700)&&errno!=EEXIST)die("private guest module directory");
            struct stat st;if(lstat(path,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=0)die("private guest module directory identity");
        }
        struct stat host_modules,guest_modules;
        subpath(path,"/data/adb/modules");
        if(stat(path,&guest_modules)||stat("/data/adb/modules",&host_modules)||guest_modules.st_dev==host_modules.st_dev)die("refuse shared host module storage");
        puts("PRIVATE_GUEST_MODULE_STORAGE145_SEPARATE_EXT4_NO_HOST_ADB_BIND");
    }
    if(server_mode){subpath(path,"/data");char value='0',readback=0;if(setxattr(path,"user.tempgsi_probe",&value,1,0)||getxattr(path,"user.tempgsi_probe",&readback,1)!=1||readback!=value||removexattr(path,"user.tempgsi_probe"))die("private ext4 real user xattr preflight");puts("PRIVATE_EXT4_USER_XATTR_ROUNDTRIP_OK");}
    if(server_mode){subpath(path,"/metadata");if(mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV,"size=32m,mode=0755"))die("private metadata");inherit_private_directory_label("/metadata");}
    subpath(path,"/data/dalvik-cache");if(mkdir(path,0755)&&errno!=EEXIST)die("dalvik cache");
    subpath(path,"/data/system");if(mkdir(path,0755)&&errno!=EEXIST)die("private system data");
    subpath(path,"/data/system/environ");if(mkdir(path,0755)&&errno!=EEXIST)die("private environment");
    subpath(path,"/data/local");if(mkdir(path,0755)&&errno!=EEXIST)die("private local");
    subpath(path,"/data/local/tmp");if(mkdir(path,0755)&&errno!=EEXIST)die("private tmp");
    if(server_mode&&mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV,"size=64m,mode=0755"))die("private per-session runtime scratch");
    if(physical_display){subpath(path,"/data/local/tmp/modules146.active");int active=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0400);if(active<0)die("private active module list target");close(active);bind_readonly("/data/local/tmp/tempgsi-evox154/modules-work146/active",path);}
    if(physical_display){subpath(path,"/data/local/tmp/guest-root-anchor145.pid");FILE *anchor=fopen(path,"w");if(!anchor||fprintf(anchor,"%d\n",getpid())<0||fclose(anchor))die("guest root namespace anchor");}
    if(physical_display){subpath(path,"/data/local/tmp/touch-state.request");int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0660);if(fd<0||fchown(fd,1000,1000)||fchmod(fd,0660))die("private display-input state request");close(fd);}
    if(physical_display){subpath(path,"/data/local/tmp/phone-boot.log");int fd=open(path,O_CREAT|O_WRONLY,0600);if(fd<0)die("phone log target");close(fd);if(mount(phone_log_source,path,NULL,MS_BIND,NULL))die("persistent private phone log bind");}
    if(server_mode){
        char source[512];subpath(source,"/data/local/tmp/guest-fstab");FILE *fstab=fopen(source,"w");if(!fstab)die("private tmpfs fstab");
        if(fprintf(fstab,"%s /data ext4 rw,nosuid,nodev defaults\n",argv[4])<0||fclose(fstab))die("private fstab contents");
        const char *label="u:object_r:vendor_configs_file:s0";if(lsetxattr(source,"security.selinux",label,strlen(label)+1,0))die("private fstab label");
        const char *targets[]={"/vendor/etc/fstab.qcom","/vendor/etc/fstab.ramplus"};
        for(unsigned i=0;i<sizeof(targets)/sizeof(targets[0]);i++){subpath(path,targets[i]);if(!access(path,F_OK))bind_readonly(source,path);}
        puts("PRIVATE_FSTAB_TMPFS_DATA_ONLY_NO_LOGICAL_BLOCK_PARTITIONS");
    }
    if(server_mode||hardware_link_mode){subpath(path,"/data/local/tmp/vendor-compat-libs");if(mkdir(path,0755))die("vendor compat library directory");bind_readonly("/data/local/tmp/tempgsi-evox154/vendor-compat-libs",path);}
    if(server_mode||hardware_link_mode){subpath(path,"/data/local/tmp/vendor-vndk33");if(mkdir(path,0755))die("vendor VNDK directory");bind_readonly("/apex/com.android.vndk.v33/lib64",path);}
    if(server_mode||hardware_link_mode){subpath(path,"/data/local/tmp/vendor-system-compat");if(mkdir(path,0755))die("vendor system ABI directory");bind_readonly("/data/local/tmp/tempgsi-evox154/vendor-system-compat",path);}
    subpath(path,"/data/local/tmp/property-seed.bin");{FILE *out=fopen(path,"wb");if(!out)die("property seed file");if(__system_property_foreach(each_property,out))die("property enumeration");if(fclose(out))die("property seed close");}
    subpath(path,"/data/local/tmp/property-seed");{int fd=open(path,O_CREAT|O_WRONLY,0700);if(fd<0)die("property helper target");close(fd);}
    bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/property-seed171",path);
    subpath(path,"/data/local/tmp/private-selinux-mount.so");{int fd=open(path,O_CREAT|O_WRONLY,0400);if(fd<0)die("SELinux mount helper target");close(fd);}
    bind_readonly("/data/local/tmp/tempgsi-private-selinux.so",path);
    subpath(path,"/data/local/tmp/artd-session.so");{int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0400);if(fd<0)die("artd session helper target");close(fd);}bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/artd-session.so",path);
    subpath(path,"/data/local/tmp/runtime-smoke.jar");{int fd=open(path,O_CREAT|O_WRONLY,0400);if(fd<0)die("jar target");close(fd);}
    bind_readonly(wifi_takeover?"/data/local/tmp/tempgsi-runtime-smoke122.jar":"/data/local/tmp/tempgsi-runtime-smoke122.jar",path);
    if(server_mode){subpath(path,"/data/local/tmp/soft-keymintd");int fd=open(path,O_CREAT|O_WRONLY,0700);if(fd<0)die("software keymint target");close(fd);bind_readonly("/data/local/tmp/tempgsi-soft-keymintd",path);}
    if(server_mode&&!access("/data/local/tmp/tempgsi-control.apk",F_OK)){subpath(path,"/data/local/tmp/controller.apk");int fd=open(path,O_CREAT|O_WRONLY,0400);if(fd<0)die("guest controller target");close(fd);bind_readonly("/data/local/tmp/tempgsi-control.apk",path);}
    /* Guest KSU namespace/UID experiment removed in profile 146. */
    subpath(path,"/data/local/tmp/dlopen-probe");{int fd=open(path,O_CREAT|O_WRONLY,0700);if(fd<0)die("dlopen target");close(fd);}
    bind_readonly("/data/local/tmp/tempgsi-evox154/dlopen-probe156",path);
    subpath(path,"/linkerconfig");if(mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV,"size=1m,mode=0755"))die("private linkerconfig");
    inherit_private_directory_label("/linkerconfig");
    subpath(path,"/linkerconfig/ld.config.txt");{int fd=open(path,O_CREAT|O_WRONLY,0400);if(fd<0)die("linkerconfig target");close(fd);}
    bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/ld.config166.txt",path);
    if(server_mode){
        const char *dirs[]={"/data","/data/system","/data/system/environ","/data/dalvik-cache","/data/local","/data/local/tmp"};
        const char *context="u:object_r:system_data_file:s0";
        for(unsigned i=0;i<sizeof(dirs)/sizeof(dirs[0]);i++){subpath(path,dirs[i]);if(lsetxattr(path,"security.selinux",context,strlen(context)+1,0))die("private data directory label");}
    }
    if(bluetooth165){
        subpath(path,"/data/local/tmp/bluetooth-address165");
        int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd<0)die("Bluetooth pinned address target");close(fd);
        bind_readonly("/mnt/vendor/efs/bluetooth/bt_addr",path);
        close(bt_address165);bt_address165=-1;
    }
    if(camera166){
        for(unsigned n=0;n<sizeof(calibration166)/sizeof(calibration166[0]);n++){
            struct stat metadata;if(stat(calibration166[n],&metadata)||!S_ISREG(metadata.st_mode)||metadata.st_size>4096)die("camera calibration metadata");
            char target166[128];snprintf(target166,sizeof(target166),"/data/local/tmp/camera-calibration166-%u",n);
            subpath(path,target166);int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd<0)die("camera pinned calibration target");close(fd);
            bind_readonly(calibration166[n],path);
        }
    }
    if(fingerprint167){
        subpath(path,"/data/local/tmp/fingerprint-vintf167");if(mkdir(path,0755))die("fingerprint167 manifest target");bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/fingerprint-vintf",path);
        subpath(path,"/vendor/firmware_mnt");struct stat firmware167;if(stat(path,&firmware167)||!S_ISDIR(firmware167.st_mode)||access("/vendor/firmware_mnt/image/securefp.mdt",R_OK))die("fingerprint167 firmware metadata");
        bind_readonly("/vendor/firmware_mnt",path);puts("FINGERPRINT167_ORIGINAL_FIRMWARE_READONLY_NO_RAW_PARTITION");
    }
    if(gatekeeper169){subpath(path,"/data/local/tmp/gatekeeper-isolation169.so");int marker169=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(marker169<0)die("Gatekeeper169 helper target");close(marker169);bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/gatekeeper-isolation169.so",path);}
    if(fingerprint167){subpath(path,"/data/local/tmp/lineage-fingerprint170");int target170=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0700);if(target170<0)die("Fingerprint170 executable target");close(target170);bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/lineage-fingerprint170",path);}
    if(server_mode){
        subpath(path,"/data/local/tmp/UdfpsIcons198.apk");{int f=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0644);if(f<0)die("Icon175 payload target");close(f);}bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/UdfpsIcons198.apk",path);
        subpath(path,"/data/local/tmp/icon198.sh");{int f=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0644);if(f<0)die("Icon175 payload target");close(f);}bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/icon198.sh",path);
        subpath(path,"/data/local/tmp/perf198.sh");{int f=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0644);if(f<0)die("Icon175 payload target");close(f);}bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/perf198.sh",path);
    }
    if(server_mode){subpath(path,"/data/local/tmp/idle198.sh");{int f=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0644);if(f<0)die("Idle198 target");close(f);}bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/idle198.sh",path);subpath(path,"/data/local/tmp/balanced198.jar");{int f=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0644);if(f<0)die("Balanced198 helper target");close(f);}bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/work198.jar",path);}
    if(server_mode){subpath(path,"/data/local/tmp/gsionlocked-wallpaper.png");{int f=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0644);if(f<0)die("GSI wallpaper target");close(f);}bind_readonly("/data/local/tmp/tempgsi-gsionlocked198/boot-wallpaper.png",path);}
    if(server_mode){
        snapshot_apex_data_metadata();
        if(chdir(base)||syscall(SYS_pivot_root,".","mnt")||chdir("/")||chroot("."))die("private pivot root");
        if(umount2("/mnt",MNT_DETACH))die("detach old private root");
        if(mount("tmpfs","/mnt","tmpfs",MS_NOSUID|MS_NODEV,"size=16m,mode=0755"))die("private storage mountpoints");
        if(mount(NULL,"/mnt",NULL,MS_SHARED|MS_REC,NULL))die("private guest storage propagation");
        if(mkdir("/mnt/tempgsi-device-tree",0755))die("private empty device tree directory");
        const char *storage_dirs[]={"/mnt/user","/mnt/runtime","/mnt/runtime/default","/mnt/runtime/read","/mnt/runtime/write","/mnt/runtime/full","/mnt/pass_through","/mnt/installer","/mnt/androidwritable","/mnt/expand"};
        for(unsigned i=0;i<sizeof(storage_dirs)/sizeof(storage_dirs[0]);i++)if(mkdir(storage_dirs[i],0755))die("private storage directory");
    }else if(chroot(base)||chdir("/"))die("chroot");
    if(bluetooth165){
        const char *dirs[]={"/mnt/vendor","/mnt/vendor/efs","/mnt/vendor/efs/bluetooth"};
        for(unsigned n=0;n<3;n++)if(mkdir(dirs[n],0755)&&errno!=EEXIST)die("Bluetooth address parent");
        const char *target="/mnt/vendor/efs/bluetooth/bt_addr";
        int fd=open(target,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd<0)die("Bluetooth address target");close(fd);
        bind_readonly("/data/local/tmp/bluetooth-address165",target);
    }
    if(camera166){
        if(mkdir("/data/local/tmp/camera-runtime166",0755))die("camera runtime directory");
        const char *sources166[]={"/vendor/bin/hw/vendor.samsung.hardware.camera.provider-service_64","/data/local/tmp/private-selinux-mount.so"};
        const char *targets166[]={"/data/local/tmp/camera-runtime166/vendor.samsung.hardware.camera.provider-service_64","/data/local/tmp/camera-runtime166/private-selinux-mount.so"};
        for(unsigned n=0;n<2;n++){int target166=open(targets166[n],O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(target166<0)die("camera runtime file");close(target166);bind_readonly(sources166[n],targets166[n]);}
        const char *parents[]={"/efs","/efs/FactoryApp","/mnt/vendor/efs/camera"};
        for(unsigned n=0;n<3;n++)if(mkdir(parents[n],0755)&&errno!=EEXIST)die("camera calibration parent");
        for(unsigned n=0;n<sizeof(calibration166)/sizeof(calibration166[0]);n++){
            int fd=open(calibration166[n],O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd<0)die("camera calibration alias");close(fd);
            char pinned166[128];snprintf(pinned166,sizeof(pinned166),"/data/local/tmp/camera-calibration166-%u",n);bind_readonly(pinned166,calibration166[n]);
        }
    }
    if(gatekeeper169){
        const char *shim169="/data/local/tmp/camera-runtime166/gatekeeper-isolation169.so";int fd169=open(shim169,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd169<0)die("Gatekeeper169 runtime helper target");close(fd169);bind_readonly("/data/local/tmp/gatekeeper-isolation169.so",shim169);
        const char *state169="/data/local/tmp/gatekeeper-mapped169.ready";fd169=open(state169,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);char zero169='0';
        if(fd169<0||fchown(fd169,1000,1000)||write(fd169,&zero169,1)!=1)die("Gatekeeper169 mapping attestation target");close(fd169);
    }
    if(fingerprint167){int target170=open("/data/local/tmp/camera-runtime166/lineage-fingerprint170",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0700);if(target170<0)die("Fingerprint170 runtime target");close(target170);bind_readonly("/data/local/tmp/lineage-fingerprint170","/data/local/tmp/camera-runtime166/lineage-fingerprint170");}
    private_root_ready=1;
    puts("PRIVATE_NAMESPACE_READY_NO_HOST_SERVICES_STOPPED");
    if(hardware_link_mode){
        const char *files[]={
            "/vendor/bin/hw/android.hardware.wifi@1.0-service",
            "/vendor/bin/hw/android.hardware.bluetooth@1.1-service-qti",
            "/vendor/bin/hw/vendor.samsung.hardware.camera.provider-service_64",
            "/vendor/bin/hw/android.hardware.audio.service_64",
            "/vendor/lib64/hw/audio.primary.kalama.so",
            "/system/bin/wificond"
        };
        int failed=0;
        puts("HARDWARE_LINK_ONLY_NO_DAEMONS_NO_DEVICE_HANDOFF_NO_FRAMEWORK");
        for(unsigned i=0;i<sizeof(files)/sizeof(files[0]);i++){
            printf("HARDWARE_LINK_BEGIN=%s\n",files[i]);
            if(access(files[i],R_OK)){printf("HARDWARE_LINK_MISSING=%s\n",files[i]);failed++;continue;}
            char command[768];
            snprintf(command,sizeof(command),"export LD_LIBRARY_PATH=%s; exec /system/bin/linker64 --list %s",
                !strncmp(files[i],"/vendor/lib64/",14)?"/data/local/tmp/vendor-compat-libs:/vendor/lib64:/vendor/lib64/hw:/data/local/tmp/vendor-vndk33":
                !strncmp(files[i],"/vendor/",8)?"/data/local/tmp/vendor-compat-libs":"/apex/com.android.runtime/lib64/bionic:/system/lib64",files[i]);
            char *args[]={"/system/bin/sh","-c",command,NULL};
            int result=child(args);printf("HARDWARE_LINK_RESULT=%d FILE=%s\n",result,files[i]);
            if(result)failed++;
        }
        printf("HARDWARE_LINK_FAILED_COMPONENTS=%d\n",failed);
        return failed?30:0;
    }
    if(wifi_takeover){char *args[]={"/system/bin/ip","link","set","lo","up",NULL};if(child(args))die("private Wi-Fi network loopback");}
    if(server_mode){
        prepare_init_directories("/system/etc/init/hw/init.rc");
        prepare_init_directories("/system/etc/init/aconfigd.rc");
        if(!fingerprint167)private_unavailable_fingerprint();
        close(boot_kmsg_fd);boot_kmsg_fd=-1;
        label_aconfig_tree("/metadata/aconfig");
        const char *user_zero[]={"/data/user/0","/data/user_de/0","/data/system_ce/0","/data/system_de/0","/data/misc_ce/0","/data/misc_de/0","/data/vendor_de/0","/data/vendor_ce/0"};
        for(unsigned i=0;i<sizeof(user_zero)/sizeof(user_zero[0]);i++){
            mode_t mode=i<2||i>=6?0771:i<4?0770:01771;gid_t gid=i<4||i>=6?1000:9998;
            const char *label="u:object_r:system_data_file:s0";
            if((mkdir(user_zero[i],mode)&&errno!=EEXIST)||chown(user_zero[i],1000,gid)||chmod(user_zero[i],mode)||lsetxattr(user_zero[i],"security.selinux",label,strlen(label)+1,0))die("private user zero storage");
        }
        if(mkdir("/data/data",0771)&&errno!=EEXIST)die("private legacy data alias");
        const char *data_context="u:object_r:system_data_file:s0";
        if(chown("/data/data",1000,1000)||chmod("/data/data",0771)||lsetxattr("/data/data","security.selinux",data_context,strlen(data_context)+1,0))die("private primary CE data");
        if(mount("/data/data","/data/user/0",NULL,MS_BIND,NULL))die("private user zero data alias");
        // Cache belongs to guest userdata, not the nearly full GSI system image.
        if((mkdir("/data/cache",0770)&&errno!=EEXIST)||chown("/data/cache",1000,2001)||chmod("/data/cache",0770))die("guest cache metadata");
        const char *cache_context="u:object_r:cache_file:s0";
        if(lsetxattr("/data/cache","security.selinux",cache_context,strlen(cache_context)+1,0)||mount("/data/cache","/cache",NULL,MS_BIND,NULL))die("guest cache mount");
        prepare_private_data_mirror();
        if(mkdir("/data/misc/profiles/cur/0",0771)&&errno!=EEXIST)die("private user profile directory");
        if(chown("/data/misc/profiles/cur/0",1000,1000))die("private user profile owner");
        // Zygote selects one of these per-user storage views before app Java runs.
        // Vold + MediaProvider mount private FUSE here. Never bind raw media as shared storage.
        if((mkdir("/data/media",0770)&&errno!=EEXIST)||(mkdir("/data/media/0",0770)&&errno!=EEXIST))die("private media directory");
        const char *storage_context="u:object_r:mnt_user_file:s0";
        const char *views[]={"/mnt/user/0","/mnt/installer/0","/mnt/androidwritable/0","/mnt/pass_through/0","/mnt/runtime/default","/mnt/runtime/read","/mnt/runtime/write","/mnt/runtime/full"};
        for(unsigned i=0;i<sizeof(views)/sizeof(views[0]);i++){
            if((mkdir(views[i],0711)&&errno!=EEXIST)||lsetxattr(views[i],"security.selinux",storage_context,strlen(storage_context)+1,0))die("private storage view");
            char media[256];snprintf(media,sizeof(media),"%s/emulated",views[i]);
            if(mkdir(media,0755))die("private media mountpoint");
            snprintf(media,sizeof(media),"%s/self",views[i]);if(mkdir(media,0755))die("private storage self directory");
            snprintf(media,sizeof(media),"%s/self/primary",views[i]);if(symlink("../emulated/0",media))die("private primary storage alias");
        }
        // A late vold FUSE mount must reach INSTALLER and ANDROID_WRITABLE
        // app namespaces too. Keep all views on guest FUSE, never raw media.
        if(mount("/mnt/user/0","/mnt/user/0",NULL,MS_BIND,NULL)||mount(NULL,"/mnt/user/0",NULL,MS_SHARED,NULL))die("private shared storage propagation root");
        const char *installer_views[]={"/mnt/installer/0","/mnt/androidwritable/0"};
        for(unsigned i=0;i<2;i++)if(mount("/mnt/user/0",installer_views[i],NULL,MS_BIND|MS_REC,NULL))die("private installer FUSE view");
        if(mount("/mnt/user/0","/storage",NULL,MS_BIND|MS_REC,NULL))die("private system storage view");
        puts("PRIVATE_USER_ZERO_STORAGE_VIEWS_READY_NO_HOST_MEDIA");
        puts("PRIVATE_USER_ZERO_CE_DE_STORAGE_READY_TMPFS_NO_HOST_DATA");
        create_private_apex_data_directories();
        // Prevent broken vendor apps (.qms / .qtidataservices) from entering infinite crash loop
        {
            DIR *app_dir=opendir("/data/app");
            if(app_dir){
                struct dirent *de;
                while((de=readdir(app_dir))){
                    if(strstr(de->d_name,"qms")||strstr(de->d_name,"qtidataservices")){
                        char rm_cmd[256];snprintf(rm_cmd,sizeof(rm_cmd),"/system/bin/rm -rf /data/app/%s",de->d_name);
                        system(rm_cmd);
                    }
                }
                closedir(app_dir);
            }
        }
    }
    pid_t property_pid=-1;
    if(server_mode){
        property_pid=fork();if(property_pid<0)die("private property server fork");
        if(!property_pid){char *args[]={"/data/local/tmp/property-seed","--serve",NULL};char *env[]={"PATH=/system/bin","ANDROID_ROOT=/system",NULL};execve(args[0],args,env);_exit(127);}
        int ready=0;for(int retry=0;retry<50;retry++){if(!access("/dev/socket/property_service",F_OK)){ready=1;break;}usleep(100000);}
        if(!ready){kill(property_pid,SIGKILL);waitpid(property_pid,NULL,0);puts("PRIVATE_PROPERTY_SERVER_NOT_READY");return 17;}
    }else {char *args[]={"/data/local/tmp/property-seed",NULL};int result=child(args);if(result){printf("PRIVATE_PROPERTY_SEED_FAILED=%d\n",result);return 14;}}
    if(server_mode){
        boot_kmsg_fd=open("/data/local/tmp/aconfig-init.log",O_CREAT|O_TRUNC|O_WRONLY,0600);if(boot_kmsg_fd<0)die("EvoX private aconfig log");
        char *early[]={"/system/bin/aconfigd-system","early-platform-init",NULL};printf("PRIVATE_EARLY_ACONFIG_RESULT=%d\n",child(early));
        char *platform[]={"/system/bin/aconfigd-system","platform-init",NULL};printf("PRIVATE_PLATFORM_ACONFIG_RESULT=%d\n",child(platform));
        char *mainline[]={"/apex/com.android.configinfrastructure/bin/aconfigd-mainline","init",NULL};printf("PRIVATE_MAINLINE_ACONFIG_RESULT=%d\n",child(mainline));
        label_aconfig_tree("/metadata/aconfig");
    }
    {char *args[]={"/apex/com.android.sdkext/bin/derive_classpath","--override-device-sdk-version=36","--override-device-codename=REL",NULL};int result=child(args);printf("LINEAGE_DERIVE_CLASSPATH_RESULT=%d\n",result);}
    {char *args[]={"/system/bin/sh","-c","cat /data/system/environ/classpath",NULL};child(args);}
    {char *args[]={"/data/local/tmp/dlopen-probe",NULL};int library_result=child(args);
        printf("PRIVATE_PUBLIC_LIBRARY_PREFLIGHT_RESULT=%d\n",library_result);
        if(library_result){
            if(property_pid>1){kill(property_pid,SIGKILL);waitpid(property_pid,NULL,0);}
            cleanup_private_children();return library_result;
        }
    }
    if(isolated_mode){int result=probe_isolated_services(server_mode);if(property_pid>1){kill(property_pid,SIGKILL);waitpid(property_pid,NULL,0);}cleanup_private_children();return result;}
    {char *args[]={"/system/bin/sh","-c","echo GSI_ANDROID16_SHELL_EXECUTED",NULL};shell_result=child(args);}
    {char *args[]={"/system/bin/linker64","--list","/system/bin/surfaceflinger",NULL};sf_result=child(args);}
    {char *args[]={"/system/bin/linker64","--list","/system/bin/app_process64",NULL};app_result=child(args);}
    {char *args[]={"/apex/com.android.art/bin/dalvikvm64","-Xusejit:false","-Xnoimage-dex2oat","-Ximage:/no-boot-image/boot.art","-Xbootclasspath:/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.i18n/javalib/core-icu4j.jar","-cp","/data/local/tmp/runtime-smoke.jar","RuntimeSmoke",NULL};vm_result=child(args);}
    {char *args[]={"/system/bin/sh","-c","while read command name value; do [ \"$command\" = export ] || exit 2; export \"$name=$value\" || exit 3; done < /data/system/environ/classpath; export CLASSPATH=/data/local/tmp/runtime-smoke.jar; exec /system/bin/app_process64 -Xusejit:false -Xnoimage-dex2oat -Ximage:/no-boot-image/boot.art -Xms16m -Xmx256m /system/bin RuntimeSmoke --android-runtime --egl",NULL};jni_result=child(args);}
    if(access("/data/local/tmp/android-runtime.ok",F_OK)) {puts("ANDROID_RUNTIME_JAVA_MAIN_NOT_REACHED");jni_result=11;}
    if(access("/data/local/tmp/vendor-egl.ok",F_OK)) {puts("VENDOR_EGL_NOT_INITIALIZED");jni_result=15;}
    zygote_result=jni_result?13:probe_zygote(0);
    printf("PROBE_RESULTS shell=%d surfaceflinger_link=%d app_process_link=%d java_vm=%d android_runtime=%d zygote=%d\n",shell_result,sf_result,app_result,vm_result,jni_result,zygote_result);
    puts("FRAMEWORK_NOT_STARTED_HOST_ONEUI_UNCHANGED");
    return shell_result||sf_result||app_result||vm_result||jni_result||zygote_result?10:0;
}
