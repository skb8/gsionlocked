/* Read-only live evidence. No ioctl setters, fd adoption, process control or mounts. */
#ifndef PD2425_PROBE_JSON_H
#define PD2425_PROBE_JSON_H
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include "identity.h"
#include "return_keys.h"

struct observed_service {const char *name,*exe;struct pd_identity identity;};
#include "services.generated.h"

/* Only the test binary accepts a fixture root; production ignores environment. */
static const char *probe_path(const char *path,char buffer[PATH_MAX]) {
#ifdef PD2425_TESTING
    const char *root=getenv("PD2425_FIXTURE_ROOT");
    if(root && *root){if(snprintf(buffer,PATH_MAX,"%s%s",root,path)>=PATH_MAX){errno=ENAMETOOLONG;return NULL;}return buffer;}
#else
    (void)buffer;
#endif
    return path;
}
static void json_string(const char *s) {
    putchar('"');
    for(const unsigned char *p=(const unsigned char*)s;*p;p++) {
        if(*p=='"'||*p=='\\'){putchar('\\');putchar(*p);}
        else if(*p<32 || *p>=127)printf("\\u%04x",*p);
        else putchar(*p);
    }
    putchar('"');
}
static int read_text(const char *path,char *out,size_t capacity) {
    char full[PATH_MAX];const char *mapped=probe_path(path,full);out[0]=0;
    if(!mapped)return errno;
    int fd=open(mapped,O_RDONLY|O_CLOEXEC|O_NONBLOCK);if(fd<0)return errno;
    ssize_t n;do{n=read(fd,out,capacity-1);}while(n<0&&errno==EINTR);
    int error=n<0?errno:0;
    if(n>=0){out[n]=0;if(n==(ssize_t)capacity-1)error=EOVERFLOW;}
    close(fd);return error;
}
static int read_link(const char *path,char *out,size_t capacity) {
    char full[PATH_MAX];const char *mapped=probe_path(path,full);out[0]=0;if(!mapped)return errno;
    ssize_t n=readlink(mapped,out,capacity-1);if(n<0)return errno;
    out[n]=0;return n==(ssize_t)capacity-1?EOVERFLOW:0;
}
static void json_file(const char *path) {
    char value[512];int error=read_text(path,value,sizeof(value));
    fputs("{\"value\":",stdout);json_string(value);printf(",\"errno\":%d}",error);
}
static unsigned long long process_start(const char *stat) {
    /* /proc/pid/stat field 22, after the possibly parenthesized comm field. */
    const char *p=strrchr(stat,')');if(!p||p[1]!=' ')return 0;p+=2;
    for(int i=0;i<19;i++){while(*p&&!isspace((unsigned char)*p))p++;while(isspace((unsigned char)*p))p++;if(!*p)return 0;}
    if(!isdigit((unsigned char)*p))return 0;
    errno=0;char *end;unsigned long long value=strtoull(p,&end,10);
    return errno||(*end&&!isspace((unsigned char)*end))?0:value;
}
static long parse_pid(const char *raw) {
    if(!isdigit((unsigned char)*raw))return -1;
    errno=0;char *end;long pid=strtol(raw,&end,10);
    return errno||*end||pid<=1||pid>INT_MAX?-1:pid;
}
static int status_field(const char *status,const char *key,char value[256]) {
    size_t size=strlen(key);value[0]=0;
    for(const char *p=status;*p;){
        const char *end=strchr(p,'\n');if(!end)end=p+strlen(p);
        if((size_t)(end-p)>=size&&!strncmp(p,key,size)) {
            p+=size;while(p<end&&isspace((unsigned char)*p))p++;
            size_t n=(size_t)(end-p);if(n>=256)return EOVERFLOW;
            memcpy(value,p,n);value[n]=0;return 0;
        }
        p=*end?end+1:end;
    }
    return ENODATA;
}
/* An executable match is evidence about a process, not proof of init ownership. */
static long executable_candidate(const char *expected,int *count,int *scan_error) {
    char full[PATH_MAX];const char *proc=probe_path("/proc",full);
    DIR *dir=proc?opendir(proc):NULL;*count=0;*scan_error=dir?0:errno;if(!dir)return -1;
    struct dirent *entry;long candidate=-1;int scanned=0;
    while((entry=readdir(dir))&&scanned<4096){
        long pid=parse_pid(entry->d_name);if(pid<2)continue;scanned++;
        char path[128],exe[512];snprintf(path,sizeof(path),"/proc/%ld/exe",pid);
        int error=read_link(path,exe,sizeof(exe));
        if(error){if(error!=ENOENT&&error!=ESRCH)*scan_error=error;continue;}
        if(!strcmp(exe,expected)){(*count)++;candidate=pid;}
    }
    if(scanned>=4096)*scan_error=EOVERFLOW;
    closedir(dir);return *count==1 && *scan_error!=EOVERFLOW?candidate:-1;
}
static void service_evidence(const struct observed_service *s) {
    char key[128],state[PROP_VALUE_MAX],pid_raw[PROP_VALUE_MAX],state_after[PROP_VALUE_MAX],pid_after[PROP_VALUE_MAX];
    snprintf(key,sizeof(key),"init.svc.%s",s->name);__system_property_get(key,state);
    snprintf(key,sizeof(key),"init.svc_debug_pid.%s",s->name);__system_property_get(key,pid_raw);
    long pid=parse_pid(pid_raw);int candidates=0,candidate_error=0;const char *pid_source=pid>1?"init_property":"unavailable";
    if(pid<2&&!*pid_raw&&!strcmp(state,"running")){
        pid=executable_candidate(s->exe,&candidates,&candidate_error);
        if(pid>1)pid_source="exe_candidate";
    }
    char path[128],before[2048]="",after[2048]="",status[8192]="",label[256]="",exe[512]="";
    int stat_error=ENODATA,status_error=ENODATA,label_error=ENODATA,exe_error=ENODATA,stable=0;
    if(pid>1) {
        snprintf(path,sizeof(path),"/proc/%ld/stat",pid);stat_error=read_text(path,before,sizeof(before));
        snprintf(path,sizeof(path),"/proc/%ld/status",pid);status_error=read_text(path,status,sizeof(status));
        snprintf(path,sizeof(path),"/proc/%ld/attr/current",pid);label_error=read_text(path,label,sizeof(label));
        snprintf(path,sizeof(path),"/proc/%ld/exe",pid);exe_error=read_link(path,exe,sizeof(exe));
        char status2[8192],label2[256],exe2[512];
        snprintf(path,sizeof(path),"/proc/%ld/status",pid);int e1=read_text(path,status2,sizeof(status2));
        snprintf(path,sizeof(path),"/proc/%ld/attr/current",pid);int e2=read_text(path,label2,sizeof(label2));
        snprintf(path,sizeof(path),"/proc/%ld/exe",pid);int e3=read_link(path,exe2,sizeof(exe2));
        /* Process memory statistics can change; compare only credential fields. */
        char uid1[256],uid2[256],gid1[256],gid2[256],groups1[256],groups2[256],caps1[256],caps2[256];
        int credentials=status_field(status,"Uid:",uid1)|status_field(status2,"Uid:",uid2)|status_field(status,"Gid:",gid1)|status_field(status2,"Gid:",gid2)|status_field(status,"Groups:",groups1)|status_field(status2,"Groups:",groups2)|status_field(status,"CapEff:",caps1)|status_field(status2,"CapEff:",caps2);
        snprintf(path,sizeof(path),"/proc/%ld/stat",pid);int end_error=read_text(path,after,sizeof(after));
        snprintf(key,sizeof(key),"init.svc_debug_pid.%s",s->name);__system_property_get(key,pid_after);
        snprintf(key,sizeof(key),"init.svc.%s",s->name);__system_property_get(key,state_after);
        unsigned long long start=process_start(before);
        stable=!stat_error&&!end_error&&!status_error&&!label_error&&!exe_error&&!e1&&!e2&&!e3&&!credentials&&start&&start==process_start(after)&&!strcmp(pid_raw,pid_after)&&!strcmp(state,state_after)&&!strcmp(state,"running")&&!strcmp(label,label2)&&!strcmp(exe,exe2)&&!strcmp(uid1,uid2)&&!strcmp(gid1,gid2)&&!strcmp(groups1,groups2)&&!strcmp(caps1,caps2);
    }
    fputs("{\"name\":",stdout);json_string(s->name);fputs(",\"expected_executable\":",stdout);json_string(s->exe);
    fputs(",\"state\":",stdout);json_string(state);
    fputs(",\"pid_source\":",stdout);json_string(pid_source);printf(",\"candidate_count\":%d,\"candidate_scan_errno\":%d",candidates,candidate_error);
    printf(",\"pid\":%ld,\"snapshot_stable\":%s,\"start_ticks\":%llu",pid,stable?"true":"false",process_start(before));
    fputs(",\"executable\":",stdout);json_string(exe);printf(",\"executable_errno\":%d,\"executable_matches\":%s",exe_error,!exe_error&&!strcmp(exe,s->exe)?"true":"false");
    fputs(",\"selinux_context\":",stdout);json_string(label);printf(",\"selinux_errno\":%d,\"status_errno\":%d,\"stat_errno\":%d",label_error,status_error,stat_error);
    const char *fields[]={"Uid:","Gid:","Groups:","CapEff:"};const char *names[]={"uid","gid","groups","cap_eff"};
    for(unsigned i=0;i<4;i++){char value[256];int error=status_field(status,fields[i],value);printf(",\"%s\":",names[i]);json_string(value);printf(",\"%s_errno\":%d",names[i],error);}
    char identity_uid[256],identity_gid[256],identity_groups[256],identity_caps[256];
    int identity_errors=status_field(status,"Uid:",identity_uid)|status_field(status,"Gid:",identity_gid)|status_field(status,"Groups:",identity_groups)|status_field(status,"CapEff:",identity_caps);
    int identity_ok=stable&&!identity_errors&&!strcmp(pid_source,"init_property")&&!strcmp(exe,s->exe)&&pd_identity_matches(&s->identity,identity_uid,identity_gid,identity_groups,identity_caps,label)==1;
    fputs(",\"identity_matches\":",stdout);fputs(!s->identity.known?"null":identity_ok?"true":"false",stdout);
    putchar('}');
}
static int bit_present(const unsigned char *bits,unsigned code){return !!(bits[code/8]&(1U<<(code%8)));}
static void input_evidence(void) {
    fputs("{\"devices\":[",stdout);int first=1,denied=0,other_errors=0;struct pd_return_keys selected={.up_index=-1,.down_index=-1};
    for(int i=0;i<64;i++) {
        char path[64],full[PATH_MAX],name[128]={0};snprintf(path,sizeof(path),"/dev/input/event%d",i);
        const char *mapped=probe_path(path,full);if(!mapped)continue;
        int fd=open(mapped,O_RDONLY|O_NONBLOCK|O_CLOEXEC);if(fd<0){if(errno==EACCES||errno==EPERM)denied++;else if(errno!=ENOENT)other_errors++;continue;}
        unsigned char keys[(KEY_MAX+8)/8]={0};
        int name_error=ioctl(fd,EVIOCGNAME(sizeof(name)),name)<0?errno:0;
        name[sizeof(name)-1]=0;int keys_error=ioctl(fd,EVIOCGBIT(EV_KEY,sizeof(keys)),keys)<0?errno:0;close(fd);
        pd_return_key_consider(&selected,i,PD_KEY_UP_NAME,PD_KEY_DOWN_NAME,name,name_error|keys_error,bit_present(keys,KEY_VOLUMEUP),bit_present(keys,KEY_VOLUMEDOWN),bit_present(keys,BTN_TOUCH));
        if(!first)putchar(',');
        first=0;
        fputs("{\"path\":",stdout);json_string(path);fputs(",\"name\":",stdout);json_string(name);
        printf(",\"name_errno\":%d,\"keys_errno\":%d,\"volume_up\":%s,\"volume_down\":%s,\"touch\":%s}",name_error,keys_error,!keys_error&&bit_present(keys,KEY_VOLUMEUP)?"true":"false",!keys_error&&bit_present(keys,KEY_VOLUMEDOWN)?"true":"false",!keys_error&&bit_present(keys,BTN_TOUCH)?"true":"false");
    }
    int valid=pd_return_keys_valid(&selected);char up[64]="",down[64]="";
    if(valid){snprintf(up,sizeof(up),"/dev/input/event%d",selected.up_index);snprintf(down,sizeof(down),"/dev/input/event%d",selected.down_index);}
    printf("],\"denied\":%d,\"other_open_errors\":%d,\"scan_limit\":64,\"return_keys\":{\"selection_valid\":%s,\"up_candidates\":%u,\"down_candidates\":%u,\"up_path\":",denied,other_errors,valid?"true":"false",selected.up_count,selected.down_count);
    json_string(up);fputs(",\"down_path\":",stdout);json_string(down);fputs(",\"physical_chord_tested\":false}}",stdout);
}
static void watchdog_inventory(void) {
    char full[PATH_MAX];const char *root=probe_path("/sys/class/watchdog",full);
    DIR *dir=root?opendir(root):NULL;int error=dir?0:errno;struct dirent *entry;unsigned count=0;
    printf("{\"class_errno\":%d,\"devices\":[",error);
    while(dir&&(entry=readdir(dir))&&count<16){
        const char *name=entry->d_name;if(strncmp(name,"watchdog",8))continue;
        const char *end=name+8;if(!*end)continue;while(isdigit((unsigned char)*end))end++;
        if(*end||strlen(name)>20)continue;
        if(count++)putchar(',');
        fputs("{\"name\":",stdout);json_string(name);
        const char *fields[]={"identity","timeout","nowayout","state"};
        for(unsigned i=0;i<4;i++){char path[128];putchar(',');json_string(fields[i]);putchar(':');snprintf(path,sizeof(path),"/sys/class/watchdog/%.20s/%s",name,fields[i]);json_file(path);}putchar('}');
    }
    if(dir)closedir(dir);
    printf("],\"scan_limited\":%s,\"note\":\"No device open or fd adoption; missing class entries do not prove no OEM watchdog exists\"}",count>=16?"true":"false");
}
static void watchdog_evidence(void) {
    const char *fields[]={"identity","timeout","nowayout","state"};putchar('{');
    for(unsigned i=0;i<4;i++){char path[128];if(i)putchar(',');json_string(fields[i]);putchar(':');snprintf(path,sizeof(path),"/sys/class/watchdog/watchdog0/%s",fields[i]);json_file(path);}
    fputs(",\"system_server_fds\":[",stdout);
    char full[PATH_MAX];const char *proc=probe_path("/proc",full);
    DIR *processes=proc?opendir(proc):NULL;int scan_errno=processes?0:errno,first=1,scanned=0,owners=0;
    struct dirent *entry;
    while(processes&&(entry=readdir(processes))&&scanned<4096&&owners<16){
        long pid=parse_pid(entry->d_name);if(pid<2)continue;scanned++;
        char path[128],comm[64];snprintf(path,sizeof(path),"/proc/%ld/comm",pid);
        if(read_text(path,comm,sizeof(comm))||strcmp(comm,"system_server\n"))continue;
        snprintf(path,sizeof(path),"/proc/%ld/fd",pid);char mapped[PATH_MAX];const char *fds_path=probe_path(path,mapped);
        DIR *fds=fds_path?opendir(fds_path):NULL;if(!fds){scan_errno=errno;continue;}
        struct dirent *fd_entry;
        while((fd_entry=readdir(fds))&&owners<16){
            const char *number=fd_entry->d_name;if(!*number)continue;
            const char *end=number;while(isdigit((unsigned char)*end))end++;if(*end||strlen(number)>10)continue;
            char link[128];snprintf(path,sizeof(path),"/proc/%ld/fd/%.10s",pid,number);
            if(read_link(path,link,sizeof(link))||(strcmp(link,"/dev/watchdog")&&strcmp(link,"/dev/watchdog0")))continue;
            if(!first)putchar(',');
            first=0;owners++;
            printf("{\"pid\":%ld,\"fd\":",pid);json_string(number);fputs(",\"target\":",stdout);json_string(link);putchar('}');
        }
        closedir(fds);
    }
    if(processes)closedir(processes);
    printf("],\"owner_scan_errno\":%d,\"owner_scan_limited\":%s,\"fd_adoption_tested\":false}",scan_errno,scanned>=4096||owners>=16?"true":"false");
}
/* Directory metadata only: do not read gesture, IMEI or calibration attributes. */
static void json_node_directory(const char *path) {
    char full[PATH_MAX];const char *mapped=probe_path(path,full);DIR *dir=mapped?opendir(mapped):NULL;
    int error=dir?0:errno;unsigned count=0;struct dirent *entry;
    printf("{\"errno\":%d,\"entries\":[",error);
    while(dir&&(entry=readdir(dir))&&count<64){
        if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
        if(count++)putchar(',');
        struct stat info;int stat_error=fstatat(dirfd(dir),entry->d_name,&info,AT_SYMLINK_NOFOLLOW)?errno:0;
        fputs("{\"name\":",stdout);json_string(entry->d_name);
        printf(",\"errno\":%d,\"mode\":%u,\"uid\":%lu,\"gid\":%lu}",stat_error,stat_error?0U:(unsigned)info.st_mode,stat_error?0UL:(unsigned long)info.st_uid,stat_error?0UL:(unsigned long)info.st_gid);
    }
    if(dir)closedir(dir);
    printf("],\"limited\":%s,\"attribute_values_read\":false}",count>=64?"true":"false");
}
/* Candidate module names only: never export kernel addresses or raw lines. */
static void json_touch_modules(void) {
    char full[PATH_MAX];const char *mapped=probe_path("/proc/modules",full);FILE *file=mapped?fopen(mapped,"re"):NULL;
    int error=file?0:errno;unsigned count=0;char line[1024];int continuation=0;
    fputs("{\"names\":[",stdout);
    while(file&&fgets(line,sizeof(line),file)&&count<32){
        int skip=continuation;continuation=strchr(line,'\n')==NULL;
        if(skip)continue;
        char name[96];if(sscanf(line,"%95s",name)!=1)continue;
        if(!strcasestr(name,"touch")&&!strcasestr(name,"vts")&&!strcasestr(name,"vivo_ts")&&!strcasestr(name,"goodix")&&!strcasestr(name,"watchdog")&&!strcasestr(name,"wdog")&&!strcasestr(name,"kernelsu"))continue;
        if(count++)putchar(',');
        json_string(name);
    }
    if(file){if(ferror(file))error=errno?errno:EIO;fclose(file);}
    printf("],\"errno\":%d,\"limited\":%s,\"raw_lines_exported\":false}",error,count>=32?"true":"false");
}
static void pd2425_json_report(int matched,const char *device,const char *sdk,const char *abi,const char *fp) {
    fputs("{\"schema\":3,\"component\":",stdout);json_string(COMPONENT);
    printf(",\"runtime_ready\":false,\"no_device_changes\":true,\"host_profile_match\":%s,\"ota_identity_match\":%s,\"uid\":%lu",matched?"true":"false",matched&&!strcmp(fp,PD2425_FINGERPRINT)?"true":"false",(unsigned long)getuid());
    const char *names[]={"device","sdk","abi","fingerprint"};const char *values[]={device,sdk,abi,fp};
    for(unsigned i=0;i<4;i++){putchar(',');json_string(names[i]);putchar(':');json_string(values[i]);}
    fputs(",\"kernel\":",stdout);json_file("/proc/sys/kernel/osrelease");
    fputs(",\"root_context\":",stdout);json_file("/proc/self/attr/current");
    fputs(",\"self_cgroup\":",stdout);json_file("/proc/self/cgroup");
    fputs(",\"boot_id\":",stdout);json_file("/proc/sys/kernel/random/boot_id");
    fputs(",\"boot_properties\":{",stdout);
    const char *properties[]={"ro.boot.flash.locked","ro.boot.verifiedbootstate","ro.boot.vbmeta.device_state","sys.boot_completed"};
    for(unsigned i=0;i<4;i++){char value[PROP_VALUE_MAX];__system_property_get(properties[i],value);if(i)putchar(',');json_string(properties[i]);putchar(':');json_string(value);}putchar('}');
    char cgpath[PATH_MAX];const char *cg=probe_path("/sys/fs/cgroup",cgpath);struct statfs fs;int fs_error=cg&&statfs(cg,&fs)==0?0:errno;
    printf(",\"cgroup_filesystem\":{\"errno\":%d,\"type\":%lu,\"is_cgroup2\":%s}",fs_error,fs_error?0UL:(unsigned long)fs.f_type,!fs_error&&(unsigned long)fs.f_type==0x63677270UL?"true":"false");
    fputs(",\"selinux_enforce\":",stdout);json_file("/sys/fs/selinux/enforce");
    fputs(",\"battery_temp\":",stdout);json_file("/sys/class/power_supply/battery/temp");
    fputs(",\"cgroup_controllers\":",stdout);json_file("/sys/fs/cgroup/cgroup.controllers");
    fputs(",\"watchdog\":",stdout);watchdog_evidence();
    fputs(",\"watchdog_class\":",stdout);watchdog_inventory();
    fputs(",\"touch_nodes\":{\"vts\":",stdout);json_node_directory("/sys/class/vts/vivo_ts");
    fputs(",\"touchscreen\":",stdout);json_node_directory("/sys/touchscreen");
    fputs(",\"module_parameters\":",stdout);json_node_directory("/sys/module/goodix_ts/parameters");
    fputs(",\"status_entries\":",stdout);json_node_directory("/sys/class/vts/vivo_ts/status");putchar('}');
    fputs(",\"module_candidates\":",stdout);json_touch_modules();
    fputs(",\"inputs\":",stdout);input_evidence();
    fputs(",\"services\":[",stdout);
    for(unsigned i=0;i<sizeof(pd_services)/sizeof(pd_services[0]);i++){if(i)putchar(',');service_evidence(&pd_services[i]);}
    puts("],\"limitations\":\"Observations only: no watchdog fd adoption, input event reading, HAL handoff or host restoration validation. Root implementation is not verified.\"}");
}
#endif
