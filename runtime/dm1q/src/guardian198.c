// Bounded host-side display lease. Never runs inside the GSI mount namespace.
#define _GNU_SOURCE
#include "background_uid_lease.h"
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/input.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include "host_softdog.h"
#include "host_ksu_restore147.h"
#include "host_thermal.h"
#include "wifi_handoff.h"
#include "cgroup_drain160.h"
#include "hal_service_lease159.h"
static long long monotonic_ms(void);
static int radio_watch139=-1;
static int mobile_watch143=-1;
static char repair_usb_config[PROP_VALUE_MAX];
static int repair_usb_during_guest;
static int read_repair_usb_config(void){
    __system_property_get("sys.usb.config",repair_usb_config);
    return !strcmp(repair_usb_config,"sec_charging,adb")||!strcmp(repair_usb_config,"adb")||!strcmp(repair_usb_config,"mtp,adb");
}
static void rebind_existing_adb(void){
    puts("HOST_USB_REBIND_EXISTING_ADB_CONFIGURATION_BEGIN");
    if(__system_property_set("sys.usb.config","none")){puts("HOST_USB_REBIND_NONE_REQUEST_FAILED");return;}
    for(int n=0;n<50;n++){char state[PROP_VALUE_MAX];__system_property_get("sys.usb.state",state);if(!strcmp(state,"none"))break;usleep(20000);}
    int result=-1;for(int n=0;n<3;n++){result=__system_property_set("sys.usb.config",repair_usb_config);if(!result)break;usleep(250000);}
    printf("HOST_USB_EXISTING_ADB_CONFIGURATION_REASSERTED=%d\n",!result);
}
struct touch_bridge {int request,changes,driver,last;long long heartbeat;};
static int apply_touch_state(struct touch_bridge *bridge){
    char state[4];ssize_t count=pread(bridge->request,state,sizeof(state),0);
    if(count==0)return 0;
    if(count!=1||(state[0]!='0'&&state[0]!='1')){puts("DISPLAY_TOUCH_STATE_INVALID");return -1;}
    bridge->heartbeat=monotonic_ms();if(bridge->heartbeat<0)return -1;
    int active=state[0]=='1';if(active==bridge->last)return 0;
    // Verified against this phone's stm_ts_spi.ko enabled_store(): normal
    // DISPLAY_STATE_ON/LATE = 2,1; DISPLAY_STATE_OFF/EARLY = 1,0.
    if(lseek(bridge->driver,0,SEEK_SET)<0||write(bridge->driver,active?"2,1":"1,0",3)!=3){perror("Samsung display/input state");return -1;}
    bridge->last=active;printf("DISPLAY_TOUCH_HARDWARE_ACTIVE=%d\n",active);return 0;
}
struct volume_chord {int up,down;long long since;};
static long long monotonic_ms(void){struct timespec now;if(clock_gettime(CLOCK_MONOTONIC,&now))return -1;return (long long)now.tv_sec*1000+now.tv_nsec/1000000;}
static int volume_event(struct volume_chord *keys,int code,int value,long long now){
    if(code==KEY_VOLUMEUP)keys->up=value!=0;
    if(code==KEY_VOLUMEDOWN)keys->down=value!=0;
    if(!keys->up||!keys->down){keys->since=-1;return 0;}
    if(keys->since<0)keys->since=now;
    return now-keys->since>=2000;
}
static int open_volume_keys(int descriptors[2]){
    int found=0;for(int index=0;index<48&&found<2;index++){
        char path[64],name[80]={0};snprintf(path,sizeof(path),"/dev/input/event%d",index);
        int fd=open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC);if(fd<0)continue;
        if(ioctl(fd,EVIOCGNAME(sizeof(name)),name)>=0&&(!strcmp(name,"gpio-keys")||!strcmp(name,"pmic_resin"))){descriptors[found++]=fd;printf("DISPLAY_RETURN_KEY_SOURCE=%s_NAME=%s\n",path,name);}else close(fd);
    }return found;
}
static int wait_for_return(int task,int signal_fd,int seconds,int keys[2],int count,struct touch_bridge *touch,int softdog,int thermal){
    struct pollfd ready[5]={{.fd=task,.events=POLLIN},{.fd=signal_fd,.events=POLLIN}};
    for(int i=0;i<count;i++)ready[i+2]=(struct pollfd){.fd=keys[i],.events=POLLIN};
    ready[2+count]=(struct pollfd){.fd=touch->changes,.events=POLLIN};
    struct volume_chord chord={.since=-1};long long start=monotonic_ms();if(start<0)return -1;
    long long next_ping=start+10000;
    long long next_thermal=start,next_thermal_log=start;int thermal_warning=0;
    int usb_rebound=!repair_usb_during_guest;long long usb_at=start+15000;
    for(;;){
        long long before=monotonic_ms();if(before<0)return -1;
        int delay=-1;
        {long long left=next_thermal-before;delay=left>0?(int)left:0;}
        if(seconds){long long left=(long long)seconds*1000-(before-start);int timeout_delay=left>0?(int)left:0;if(timeout_delay<delay)delay=timeout_delay;}
        if(chord.up&&chord.down){long long left=2000-(before-chord.since);int key_delay=left>0?(int)left:0;if(delay<0||key_delay<delay)delay=key_delay;}
        if(softdog>=0){long long left=next_ping-before;int watchdog_delay=left>0?(int)left:0;if(delay<0||watchdog_delay<delay)delay=watchdog_delay;}
        if(!usb_rebound){long long left=usb_at-before;int usb_delay=left>0?(int)left:0;if(delay<0||usb_delay<delay)delay=usb_delay;}
        int result=poll(ready,3+count,delay);if(result<0){if(errno==EINTR)continue;return -1;}
        long long now=monotonic_ms();if(now<0)return -1;
        if(active_bg_group&&bg_group_tick(active_bg_group,now)){puts("GUEST_UID_NETWORK_LEASE_REFRESH_FAILED_RETURNING_ONEUI");return -1;}
        if(radio_watch139>=0){struct pollfd radio={.fd=radio_watch139,.events=POLLIN};if(poll(&radio,1,0)!=0){puts("RADIO_GUEST_RIL_EXITED_RETURNING_ONEUI");return -1;}}
        if(mobile_watch143>=0){struct pollfd mobile={.fd=mobile_watch143,.events=POLLIN};if(poll(&mobile,1,0)!=0){puts("RADIO_MOBILE143_KEEPER_EXITED_RETURNING_ONEUI");return -1;}}
        if(ready[0].revents){puts("DISPLAY_GUEST_TARGET_EXITED_RETURNING_ONEUI");return 0;}
        if(ready[1].revents){puts("DISPLAY_GUARDIAN_RETURN_SIGNAL_RECEIVED");return 0;}
        if(now>=next_thermal){
            int temperature;
            if(read_battery_temperature(thermal,&temperature)){puts("THERMAL_SENSOR_LOST_RETURNING_ONEUI");return 0;}
            int action=battery_temperature_action(temperature,0);
            if(now>=next_thermal_log||action!=thermal_warning){printf("HOST_THERMAL_BATTERY_TENTHS_C=%d\n",temperature);next_thermal_log=now+10000;}
            thermal_warning=action;next_thermal=now+TEMP_SAMPLE_MS;
            if(action==2){puts("THERMAL_BATTERY_LIMIT_RETURNING_ONEUI");return 0;}
            if(action==1)puts("THERMAL_BATTERY_WARM_WARNING");
        }
        if(!usb_rebound&&now>=usb_at){rebind_existing_adb();usb_rebound=1;}
        if(ready[2+count].revents&POLLIN){char events[1024];while(read(touch->changes,events,sizeof(events))>0){}if(apply_touch_state(touch))return -1;}
        if(softdog>=0&&now>=next_ping){
            if(now-start>60000&&(!touch->heartbeat||now-touch->heartbeat>20000)){puts("DISPLAY_GUEST_POWER_HEARTBEAT_LOST_RETURNING_HOST");return 0;}
            if(ioctl(softdog,WDIOC_KEEPALIVE,0)){perror("host software watchdog keepalive");return -1;}
            printf("HOST_SOFTDOG_KEEPALIVE_ELAPSED_MS=%lld\n",now-start);next_ping=now+10000;
        }
        for(int i=0;i<count;i++){
            if(ready[i+2].revents&(POLLERR|POLLHUP|POLLNVAL)){puts("DISPLAY_RETURN_KEY_SOURCE_LOST_ENDING_SESSION");return -1;}
            if(ready[i+2].revents&POLLIN){struct input_event event;while(read(keys[i],&event,sizeof(event))==sizeof(event))if(event.type==EV_KEY)volume_event(&chord,event.code,event.value,now);}
        }
        if(chord.up&&chord.down&&volume_event(&chord,KEY_VOLUMEUP,1,now)){puts("DISPLAY_LEASE_RETURN_VOLUME_CHORD");return 0;}
        if(seconds&&now-start>=(long long)seconds*1000){puts("DISPLAY_LEASE_TIME_LIMIT_REACHED");return 0;}
    }
}
static int thermal_wait_loop_self_test(void){
    char file[]="/data/local/tmp/tempgsi-thermal-loop-XXXXXX";int fd=mkstemp(file);
    if(fd<0)return 26;unlink(file);
    int notifications[2],changes[2];
    if(pipe2(notifications,O_CLOEXEC)||pipe2(changes,O_CLOEXEC)){close(fd);return 26;}
    pid_t child=fork();if(child<0)return 26;if(!child){for(;;)pause();}
    int task=syscall(SYS_pidfd_open,child,0),result=0;
    struct touch_bridge touch={.request=-1,.changes=changes[0],.driver=-1,.last=-1};int keys[2]={-1,-1};
    if(task<0||write(fd,"420\n",4)!=4)result=26;
    for(int round=0;!result&&round<2;round++){
        if(round&&ftruncate(fd,0)){result=26;break;}
        long long start=monotonic_ms();
        if(wait_for_return(task,notifications[0],0,keys,0,&touch,-1,fd)||monotonic_ms()-start>1000)result=26;
        struct pollfd alive={.fd=task,.events=POLLIN};if(poll(&alive,1,0)!=0)result=26;
    }
    if(task>=0){syscall(SYS_pidfd_send_signal,task,SIGKILL,NULL,0);close(task);}else kill(child,SIGKILL);
    waitpid(child,NULL,0);close(fd);close(notifications[0]);close(notifications[1]);close(changes[0]);close(changes[1]);
    if(!result)puts("THERMAL_WAIT_LOOP_HOT_AND_LOST_SENSOR_EXIT_SELF_TEST_OK_NO_SERVICES_CHANGED");
    return result;
}
static int pidfd_open_checked(pid_t pid){return syscall(SYS_pidfd_open,pid,0);}
static int kill_fd(int fd){return syscall(SYS_pidfd_send_signal,fd,SIGKILL,NULL,0);}
static int target_waiting_for_display(long pid,int task){
    char path[64],command[2048];snprintf(path,sizeof(path),"/proc/%ld/cmdline",pid);
    for(int attempt=0;attempt<100;attempt++){
        struct pollfd alive={.fd=task,.events=POLLIN};if(poll(&alive,1,0)!=0)return 0;
        int fd=open(path,O_RDONLY|O_CLOEXEC);ssize_t count=fd>=0?read(fd,command,sizeof(command)):-1;if(fd>=0)close(fd);
        if(count>0&&memmem(command,count,"display-lease.go",16))return 1;
        usleep(20000);
    }return 0;
}
static int named_service_is(const char *name,const char *expected){char value[PROP_VALUE_MAX],key[128];snprintf(key,sizeof(key),"init.svc.%s",name);__system_property_get(key,value);return !strcmp(value,expected);}
static int stop_audio_group198(int server,int primary,int samsung){
    const char *names[]={"audioserver","vendor.audio-hal","vendor.secaudiohal-aidl"};
    int owned[]={server,primary,samsung},stable=0;
    // Samsung init starts HALs when audioserver stops. Reconcile the whole
    // group, then require a stable quiet interval before handing over devices.
    for(int tick=0;tick<160;tick++){
        int quiet=1;
        for(unsigned i=0;i<3;i++)if(owned[i]&&!named_service_is(names[i],"stopped")){
            quiet=0;
            if(tick%5==0&&__system_property_set("ctl.stop",names[i]))return -1;
        }
        if(quiet){if(++stable>=10){puts("HOST_AUDIO_GROUP_STABLY_STOPPED");return 0;}}
        else stable=0;
        usleep(50000);
    }
    puts("HOST_AUDIO_GROUP_STOP_TIMEOUT_NO_GUEST_HANDOFF");return -1;
}
static int service_is(const char *expected){return named_service_is("surfaceflinger",expected);}
static int set_service(const char *operation,const char *name,const char *state){
    if(__system_property_set(operation,name)){printf("HOST_SERVICE_REQUEST_FAILED_OPERATION=%s_NAME=%s_ERRNO=%d\n",operation,name,errno);return -1;}
    for(int i=0;i<50;i++){if(named_service_is(name,state))return 0;usleep(100000);}
    char key[128],current[PROP_VALUE_MAX];snprintf(key,sizeof(key),"init.svc.%s",name);__system_property_get(key,current);
    printf("HOST_SERVICE_STATE_TIMEOUT_NAME=%s_EXPECTED=%s_ACTUAL=%s\n",name,state,current);return -1;
}
#include "radio_handoff139.h"
static int bt_state165(void *ctx,const char *name){
    (void)ctx;if(named_service_is(name,"running"))return HAL159_RUNNING;
    return named_service_is(name,"stopped")?HAL159_STOPPED:HAL159_UNKNOWN;
}
static int bt_set165(void *ctx,const char *name,int state){
    (void)ctx;int result169=set_service(state?"ctl.start":"ctl.stop",name,state?"running":"stopped");printf("PIN169_HOST_SERVICE_CHANGE name=%s requested=%d result=%d running=%d stopped=%d\n",name,state,result169,named_service_is(name,"running"),named_service_is(name,"stopped"));return result169;
}
struct drain_context160 { int events,softdog; };
static int drain_sample160(void *opaque){
    struct drain_context160 *ctx=opaque;char data[4097];ssize_t count;
    do{count=pread(ctx->events,data,sizeof(data),0);}while(count<0&&errno==EINTR);
    return count>0?cgroup_populated160(data,(size_t)count):-1;
}
static int drain_pause160(void *opaque){
    struct drain_context160 *ctx=opaque;
    if(ctx->softdog>=0&&ioctl(ctx->softdog,WDIOC_KEEPALIVE,0))return -1;
    struct timespec remaining={.tv_sec=0,.tv_nsec=50000000};
    while(nanosleep(&remaining,&remaining))if(errno!=EINTR)return -1;
    return 0;
}
#include "../../common/host_guard.h"
int main(int argc,char **argv){
    if(require_dm1q_host())return 31;
    if(argc==2&&!strcmp(argv[1],"--check-host")){
        puts("DM1Q_HOST_MATCH_NO_CHANGES");return 0;
    }
    setbuf(stdout,NULL);
    if(argc==2&&!strcmp(argv[1],"--self-test-thermal")){
        if(getuid()!=0)return 2;
        int result=thermal_self_test();return result?result:thermal_wait_loop_self_test();
    }
    if(argc==2&&!strcmp(argv[1],"--check-thermal")){
        if(getuid()!=0)return 2;
        int fd=open(TEMP_BATTERY_PATH,O_RDONLY|O_CLOEXEC);int result=thermal_preflight(fd);if(fd>=0)close(fd);
        return result?25:0;
    }
    if(argc==2&&!strcmp(argv[1],"--check-usb-repair")){
        if(getuid()!=0||!read_repair_usb_config())return 24;
        printf("HOST_USB_REPAIR_CONFIGURATION_SUPPORTED=%s_NO_CHANGES\n",repair_usb_config);return 0;
    }
    if(argc==2&&!strcmp(argv[1],"--self-test-softdog-adoption")){
        if(getuid()!=0)return 2;int fd=adopt_host_softdog();if(fd<0)return 23;
        close(fd);puts("HOST_SOFTDOG_READ_ONLY_ADOPTION_SELF_TEST_OK_ORIGINAL_OWNER_UNCHANGED");return 0;
    }
    if(argc==2&&!strcmp(argv[1],"--self-test-readiness")){
        pid_t child=fork();if(child<0)return 20;
        if(!child){usleep(120000);execl("/system/bin/sh","sh","-c","while :; do sleep 1; done","display-lease.go",(char*)NULL);_exit(127);}
        int task=pidfd_open_checked(child);int ready=task>=0?target_waiting_for_display(child,task):0;
        if(task>=0){kill_fd(task);close(task);}else kill(child,SIGKILL);waitpid(child,NULL,0);
        if(!ready)return 20;
        puts("DISPLAY_GATE_EXEC_READINESS_RACE_SELF_TEST_OK");return 0;
    }
    if(argc==2&&!strcmp(argv[1],"--self-test-keys")){
        struct volume_chord chord={.since=-1};
        if(volume_event(&chord,KEY_VOLUMEUP,1,0)||volume_event(&chord,KEY_VOLUMEDOWN,1,100)||volume_event(&chord,KEY_VOLUMEUP,2,2099)||!volume_event(&chord,KEY_VOLUMEUP,2,2100))return 19;
        if(volume_event(&chord,KEY_VOLUMEDOWN,0,2200)||volume_event(&chord,KEY_VOLUMEDOWN,1,2300)||volume_event(&chord,KEY_VOLUMEUP,2,4299)||!volume_event(&chord,KEY_VOLUMEUP,2,4300))return 19;
        puts("DISPLAY_RETURN_TWO_SECOND_VOLUME_CHORD_SELF_TEST_OK");return 0;
    }
    if(argc==2&&!strcmp(argv[1],"--self-test")){
        pid_t child=fork();if(child<0)return 10;if(!child){for(;;)pause();}
        int fd=pidfd_open_checked(child);if(fd<0){kill(child,SIGKILL);waitpid(child,NULL,0);return 11;}
        int result=kill_fd(fd);int status=0;waitpid(child,&status,0);close(fd);
        if(result||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL)return 12;
        puts("DISPLAY_LEASE_PIDFD_SELF_TEST_OK_NO_SERVICES_CHANGED");return 0;
    }
    int repair_usb=argc==5&&!strcmp(argv[4],"--repair-adb");
    repair_usb_during_guest=repair_usb;
    int lease_pin169=argc==5&&!strcmp(argv[4],"--lease-pin169");
    int lease_fingerprint167=lease_pin169||(argc==5&&!strcmp(argv[4],"--lease-camera-fingerprint167"));
    int lease_camera166=lease_fingerprint167||(argc==5&&!strcmp(argv[4],"--lease-wifi-browser-radio-mobile143-camera166"));
    int lease_bt165=lease_camera166||(argc==5&&!strcmp(argv[4],"--lease-wifi-browser-radio-mobile143-bluetooth165"));
    int lease_mobile=lease_bt165||(argc==5&&!strcmp(argv[4],"--lease-wifi-browser-radio-mobile143"));
    int lease_radio=lease_mobile||(argc==5&&!strcmp(argv[4],"--lease-wifi-browser-radio"));
    int lease_browser=lease_radio||(argc==5&&!strcmp(argv[4],"--lease-wifi-browser"));
    int lease_wifi=argc==5&&(!strcmp(argv[4],"--lease-wifi")||lease_browser);
    int valid_args=argc==4||repair_usb||lease_wifi;
    int quiesced=valid_args&&!strcmp(argv[1],"--run-quiesced");
    if(!valid_args||(!quiesced&&strcmp(argv[1],"--run"))||getuid()!=0)return 2;
    if(repair_usb&&(!quiesced||!read_repair_usb_config()))return 24;
    if(lease_wifi&&!quiesced)return 2;
    int restore_usb_after_lease=lease_wifi&&read_repair_usb_config();
    if(lease_radio&&!lease_mobile&&(!strcmp(argv[3],"0")))return 2;
    char *end=NULL;long pid=strtol(argv[2],&end,10);if(!end||*end||pid<=1)return 2;
    long seconds=strtol(argv[3],&end,10);if(!end||*end||seconds<0||((!quiesced||seconds)&&seconds<3)||seconds>(quiesced?180:12))return 2;
    int task=pidfd_open_checked(pid);if(task<0){perror("lease pidfd");return 3;}
    char path[256];
    if(!target_waiting_for_display(pid,task)){puts("REFUSE_TARGET_NOT_WAITING_GSI_DISPLAY");return 4;}
    struct stat host,guest;snprintf(path,sizeof(path),"/proc/%ld/root/dev/binder",pid);
    if(stat("/dev/binder",&host)||stat(path,&guest)||host.st_rdev==guest.st_rdev){puts("REFUSE_SHARED_PRIMARY_BINDER");return 5;}
    struct stat root;snprintf(path,sizeof(path),"/proc/%ld/root",pid);
    if(stat("/",&root)||stat(path,&guest)||(root.st_dev==guest.st_dev&&root.st_ino==guest.st_ino)){puts("REFUSE_HOST_ROOT_TARGET");return 6;}
    int cgroup_kill=-1;char cgroup_path[256]={0},line[300];
    snprintf(path,sizeof(path),"/proc/%ld/cgroup",pid);FILE *cgroups=fopen(path,"r");
    if(cgroups){while(fgets(line,sizeof(line),cgroups)){unsigned owner;char extra;if(sscanf(line,"0::/tempgsi_session_%u%c",&owner,&extra)==2&&extra=='\n'&&owner>1){snprintf(cgroup_path,sizeof(cgroup_path),"/sys/fs/cgroup/tempgsi_session_%u",owner);snprintf(path,sizeof(path),"%s/cgroup.kill",cgroup_path);cgroup_kill=open(path,O_WRONLY|O_CLOEXEC);break;}}fclose(cgroups);}
    if(quiesced&&cgroup_kill<0){puts("REFUSE_GUEST_SESSION_WITHOUT_ATOMIC_TERMINATION");return 18;}
    int guest_events160=-1;
    if(cgroup_kill>=0){
        snprintf(path,sizeof(path),"%s/cgroup.events",cgroup_path);
        guest_events160=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        struct drain_context160 preflight={.events=guest_events160,.softdog=-1};
        if(guest_events160<0||drain_sample160(&preflight)!=1){
            puts("REFUSE_GUEST_CGROUP_STATE_UNAVAILABLE");
            if(guest_events160>=0)close(guest_events160);close(cgroup_kill);close(task);return 34;
        }
    }
    int thermal=open(TEMP_BATTERY_PATH,O_RDONLY|O_CLOEXEC);
    if(thermal_preflight(thermal)){
        if(thermal>=0)close(thermal);
        if(cgroup_kill>=0){if(write(cgroup_kill,"1",1)!=1)puts("GUEST_CGROUP_TERMINATION_FAILED");close(cgroup_kill);}else kill_fd(task);
        close(task);return 25;
    }
    if(!service_is("running")){puts("REFUSE_HOST_SURFACEFLINGER_NOT_RUNNING");return 7;}
    int volume_keys[2],volume_count=open_volume_keys(volume_keys);
    if(quiesced&&!seconds&&volume_count!=2){puts("REFUSE_UNLIMITED_SESSION_WITHOUT_PHYSICAL_RETURN_KEYS");return 19;}
    struct touch_bridge touch={.request=-1,.changes=-1,.driver=-1,.last=-1};
    snprintf(path,sizeof(path),"/proc/%ld/root/data/local/tmp/touch-state.request",pid);
    touch.request=open(path,O_RDONLY|O_CLOEXEC);touch.changes=inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
    if(touch.request<0||touch.changes<0||inotify_add_watch(touch.changes,path,IN_CLOSE_WRITE)<0){puts("REFUSE_MISSING_DISPLAY_INPUT_STATE_CHANNEL");return 21;}
    touch.driver=open("/sys/class/sec/tsp/enabled",O_WRONLY|O_CLOEXEC);
    if(touch.driver<0){puts("REFUSE_MISSING_SAMSUNG_DISPLAY_INPUT_DRIVER");return 21;}
    sigset_t signals;sigemptyset(&signals);sigaddset(&signals,SIGTERM);sigaddset(&signals,SIGINT);sigaddset(&signals,SIGHUP);
    if(sigprocmask(SIG_BLOCK,&signals,NULL))return 8;
    int signal_fd=signalfd(-1,&signals,SFD_CLOEXEC|SFD_NONBLOCK);if(signal_fd<0)return 8;
    int original_zygote=named_service_is("zygote","running"),original_secondary=named_service_is("zygote_secondary","running"),original_bootchecker=named_service_is("bootchecker","running");
    int original_audio=quiesced&&named_service_is("audioserver","running");
    int original_audio_hal=quiesced&&named_service_is("vendor.audio-hal","running"); int original_secaudio=quiesced&&named_service_is("vendor.secaudiohal-aidl","running");
    int original_netd=quiesced&&named_service_is("netd","running"),host_android_quiesced=0;
    int softdog=quiesced?adopt_host_softdog():-1;
    if(quiesced&&(softdog<0||ioctl(softdog,WDIOC_KEEPALIVE,0))){puts("REFUSE_CANNOT_MAINTAIN_HOST_SOFTWARE_WATCHDOG");if(softdog>=0)close(softdog);return 23;}
    struct hal_service_lease159 bt165={.names={"vendor.bluetooth-1-1-qti"},.count=1};
    if(lease_camera166){bt165.names[0]="sec-biometrics-face-aidl";bt165.names[1]="cameraserver";bt165.names[2]="sec-camera-provider";bt165.names[3]="vendor.bluetooth-1-1-qti";bt165.count=4;}
    if(lease_fingerprint167){bt165.names[4]="vendor.fingerprint-default";bt165.count=5;}
    struct hal_service_ops159 bt_ops165={.state=bt_state165,.set=bt_set165,.context=NULL};
    if(lease_bt165&&hal_lease159_capture(&bt165,&bt_ops165)){if(softdog>=0)close(softdog);return 35;}
    struct wifi_handoff wifi={.host=-1,.guest=-1,.moved=0};
    struct bg_uid_group browser={.directory=-1};
    struct radio_lease139 radio={.binder=-1,.hardware=-1,.mounts=-1,.task=-1,.pid=-1,.mobile=lease_mobile,.network=-1,.channel=-1,.keeper_task=-1,.keeper=-1,.owner_watched=seconds==0};
    int result=lease_wifi&&wifi_handoff_prepare(&wifi,pid)?26:0;
    if(!result&&lease_browser&&bg_group_prepare(&browser,pid)){puts("REFUSE_GUEST_UID_NETWORK_LEASE_PREPARATION");result=30;}
    if(!result&&lease_radio&&radio_prepare139(&radio,pid,cgroup_path)){puts("REFUSE_RADIO_HANDOFF_PREPARATION");result=32;}
    if(quiesced&&!result){
        puts("DISPLAY_LEASE_QUIESCE_HOST_ANDROID");
        if(set_service("ctl.stop","bootchecker","stopped"))result=16;
        if(!result&&original_secondary&&set_service("ctl.stop","zygote_secondary","stopped"))result=16;
        if(!result&&original_zygote&&set_service("ctl.stop","zygote","stopped"))result=16;
        if(original_zygote&&named_service_is("zygote","stopped"))host_android_quiesced=1;
        if(!result&&lease_bt165&&hal_lease159_acquire(&bt165,&bt_ops165)){puts("BLUETOOTH165_HOST_STOP_FAILED");result=35;}
        if(!result&&stop_audio_group198(original_audio,original_audio_hal,original_secaudio))result=28;
        if(!result&&lease_browser&&bg_group_begin(&browser)){puts("GUEST_UID_NETWORK_LEASE_FAILED");result=30;}
        if(!result&&lease_radio&&radio_start139(&radio)){puts("RADIO_HANDOFF_START_FAILED");result=32;}
        if(!result&&lease_radio)radio_watch139=radio.task;
        if(!result&&lease_mobile)mobile_watch143=radio.keeper_task;
    }
    printf("DISPLAY_LEASE_STOP_HOST_SF_TARGET=%ld_SECONDS=%ld\n",pid,seconds);
    if(!result)result=__system_property_set("ctl.stop","surfaceflinger");
    if(!result){for(int i=0;i<50&&!service_is("stopped");i++)usleep(100000);}
    if(result){printf("DISPLAY_LEASE_PREPARATION_FAILED_RETURNING_HOST_RESULT=%d\n",result);}
    else if(!service_is("stopped")){puts("DISPLAY_LEASE_STOP_FAILED");result=9;}
    else{
        if(lease_wifi&&wifi_handoff_start(&wifi,pid)){puts("WIFI_HANDOFF_FAILED_NO_GUEST_RELEASE");result=26;}
        if(!result&&lease_bt165){
            snprintf(path,sizeof(path),"/proc/%ld/root/data/local/tmp/bluetooth-handoff165.ready",pid);
            int gate=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
            if(gate<0)result=35;else{close(gate);puts("BLUETOOTH165_HOST_STOPPED_GUEST_RELEASED");}
            if(!result&&lease_camera166){
                snprintf(path,sizeof(path),"/proc/%ld/root/data/local/tmp/camera-handoff166.ready",pid);
                int camera_gate166=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
                if(camera_gate166<0)result=35;else{close(camera_gate166);puts("CAMERA166_HOST_STOPPED_GUEST_RELEASED");}
                if(!result&&lease_fingerprint167){snprintf(path,sizeof(path),"/proc/%ld/root/data/local/tmp/fingerprint-handoff167.ready",pid);int fpgate167=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);if(fpgate167<0)result=35;else{close(fpgate167);puts("FINGERPRINT167_HOST_STOPPED_GUEST_RELEASED");}if(!result&&lease_pin169){snprintf(path,sizeof(path),"/proc/%ld/root/data/local/tmp/gatekeeper-handoff169.ready",pid);int gkgate169=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);if(gkgate169<0)result=35;else{close(gkgate169);puts("GATEKEEPER169_PRIVATE_SECURE_IDS_GUEST_RELEASED");}}}

            }
        }
        if(!result){
            snprintf(path,sizeof(path),"/proc/%ld/root/data/local/tmp/audio-handoff.ready",pid);
            int audio_gate=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
            if(audio_gate<0){puts("AUDIO_HANDOFF_GATE_FAILED");result=28;}
            else{close(audio_gate);puts("HOST_AUDIO_SERVICES_STOPPED_GUEST_AUDIO_RELEASED");}
        }
        if(!result){
        snprintf(path,sizeof(path),"/proc/%ld/root/data/local/tmp/display-lease.go",pid);
        int go=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
        if(go<0){perror("lease release gate");result=13;}
        else{
            close(go);puts("DISPLAY_LEASE_GSI_RELEASED");
            if(apply_touch_state(&touch)||wait_for_return(task,signal_fd,(int)seconds,volume_keys,volume_count,&touch,softdog,thermal))result=14;
        }
        }
    }
    // PID descriptors prevent killing a reused PID. Kill the guest client first.
    if(cgroup_kill>=0){if(write(cgroup_kill,"1",1)!=1){puts("GUEST_CGROUP_TERMINATION_FAILED");result=18;kill_fd(task);}else puts("DISPLAY_LEASE_GUEST_CGROUP_KILL_REQUEST_ACCEPTED");close(cgroup_kill);}
    else kill_fd(task);
    if(guest_events160>=0){
        struct drain_context160 context={.events=guest_events160,.softdog=softdog};
        struct cgroup_drain_ops160 ops={.sample=drain_sample160,.pause=drain_pause160,.context=&context};
        int drained=cgroup_drain_wait160(&ops,301);close(guest_events160);
        if(drained){
            // Do not restart host hardware against live/unknown guest owners.
            // Existing armed watchdog remains the recovery fallback.
            puts("GUEST_CGROUP_DRAIN_UNCONFIRMED_HOST_HARDWARE_NOT_RESTARTED");
            if(softdog>=0)close(softdog);return 34;
        }
        puts("DISPLAY_LEASE_GUEST_CGROUP_DRAIN_CONFIRMED");
    }
    if(lease_bt165){int restored_bt=hal_lease159_restore(&bt165,&bt_ops165,1);printf("BLUETOOTH165_HOST_RESTORE_RESULT=%d\n",restored_bt);if(restored_bt)result=35;}
    radio_watch139=-1;
    mobile_watch143=-1;
    if(lease_radio&&radio_restore139(&radio))result=32;
    if(bg_group_restore(&browser))result=31;
    if(lease_wifi&&wifi_handoff_restore(&wifi))result=27;
    if(lseek(touch.driver,0,SEEK_SET)<0||write(touch.driver,"2,1",3)!=3)puts("DISPLAY_TOUCH_RESTORE_FAILED");
    close(touch.driver);close(touch.changes);close(touch.request);
    if(softdog>=0){
        if(ioctl(softdog,WDIOC_KEEPALIVE,0))puts("HOST_SOFTDOG_FINAL_KEEPALIVE_FAILED");
        // No magic-close write: keep the existing 100-second watchdog armed.
        // Release the exclusive open before the new stock SystemServer starts.
        close(softdog);puts("HOST_SOFTDOG_RELEASED_FOR_STOCK_SYSTEM_SERVER");
    }
    struct pollfd exited={.fd=task,.events=POLLIN};poll(&exited,1,2000);
    if(cgroup_path[0])for(int retry=0;retry<10;retry++){if(!rmdir(cgroup_path))break;usleep(100000);}
    if(original_secaudio&&set_service("ctl.start","vendor.secaudiohal-aidl","running"))result=28;
    int audio_hal_restored=original_audio_hal?set_service("ctl.start","vendor.audio-hal","running"):0;
    int audio_restored=original_audio?set_service("ctl.start","audioserver","running"):0;
    if(lease_wifi)printf("HOST_AUDIO_SERVICES_RESTORE_RESULT=%d\n",audio_hal_restored||audio_restored);
    if(audio_hal_restored||audio_restored)result=29;
    int restored=__system_property_set("ctl.start","surfaceflinger");
    if(!restored){for(int i=0;i<50&&!service_is("running");i++)usleep(100000);}
    printf("DISPLAY_LEASE_HOST_SF_RESTORED=%d\n",!restored&&service_is("running"));
    if(quiesced){
        // Android 16's DNS resolver unstable interface can be acquired only
        // once by AID_SYSTEM per netd lifetime. A fresh stock SystemServer
        // therefore needs a fresh stock netd after the guest relinquishes it.
        if(original_netd&&host_android_quiesced){
            int netd_reset=set_service("ctl.stop","netd","stopped");
            if(!netd_reset)netd_reset=set_service("ctl.start","netd","running");
            printf("HOST_NETD_FRESH_DNS_INTERFACE_RESTORE_RESULT=%d\n",netd_reset);
            if(netd_reset)result=33;
        }
        struct ksu_init_lease147 ksu_lease=ksu_init_begin147();
        int zygote_restored=original_zygote?set_service("ctl.start","zygote","running"):0;
        int secondary_restored=original_secondary?set_service("ctl.start","zygote_secondary","running"):0;
        ksu_init_end147(&ksu_lease);
        if(original_bootchecker)__system_property_set("ctl.start","bootchecker");
        printf("DISPLAY_LEASE_HOST_ZYGOTE_RESTORED=%d\n",!zygote_restored&&!secondary_restored);
        if(zygote_restored||secondary_restored)result=17;
    }
    if(restore_usb_after_lease)rebind_existing_adb();
    for(int i=0;i<volume_count;i++)close(volume_keys[i]);
    close(thermal);close(task);close(signal_fd);return restored||!service_is("running")?15:result;
}
