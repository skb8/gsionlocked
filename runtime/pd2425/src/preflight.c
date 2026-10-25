/* Diagnostic-only PD2425 port: no mounts, writes, service control or ioctl setters. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/system_properties.h>
#include "profile.h"
#ifndef COMPONENT
#define COMPONENT "preflight"
#endif
#include "probe_json.h"
int main(int argc,char **argv) {
    if(argc!=2 || (strcmp(argv[1],"--diagnose") && strcmp(argv[1],"--check-host") && strcmp(argv[1],"--diagnose-json"))) {
        fputs("PD2425_HANDOFF_UNAVAILABLE: only --diagnose / --check-host / --diagnose-json; no changes made\n",stderr);
        return 78;
    }
    char device[PROP_VALUE_MAX],sdk[PROP_VALUE_MAX],abi[PROP_VALUE_MAX],fp[PROP_VALUE_MAX];
    __system_property_get("ro.product.device",device);
    __system_property_get("ro.build.version.sdk",sdk);
    __system_property_get("ro.product.cpu.abi",abi);
    __system_property_get("ro.build.fingerprint",fp);
    int matched=pd2425_identity(device,sdk,abi,fp);
    if(!strcmp(argv[1],"--diagnose-json")){pd2425_json_report(matched,device,sdk,abi,fp);return matched?0:31;}
    printf("component=%s\ndevice=%s\nsdk=%s\nabi=%s\nfingerprint=%s\nota_identity_match=%d\n",COMPONENT,device,sdk,abi,fp,matched);
    if(!strcmp(argv[1],"--diagnose")) {
        const char *keys[]={"ro.boot.flash.locked","ro.boot.verifiedbootstate","ro.soc.model","ro.vivo.os.version","ro.vivo.product.version","init.svc.surfaceflinger","init.svc.zygote","init.svc.audioserver"};
        for(unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);i++) {
            char value[PROP_VALUE_MAX];__system_property_get(keys[i],value);printf("%s=%s\n",keys[i],value);
        }
        printf("uid=%lu\n",(unsigned long)getuid());
        FILE *f=fopen("/sys/fs/selinux/enforce","r");int mode=f?fgetc(f):EOF;if(f)fclose(f);
        printf("selinux_enforcing=%s\n",mode=='1'?"yes":mode=='0'?"no":"unreadable");
        printf("cgroup_v2_visible=%d\n",access("/sys/fs/cgroup/cgroup.controllers",R_OK)==0);
    }
    puts("runtime_ready=0\nreason=unvalidated_display_input_watchdog_HAL_SELinux_restore\nno_changes=1");
    return matched?0:31;
}
