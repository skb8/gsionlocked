/* PD2425 diagnostics plus explicit own-child tests. No guest or host service control. */
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
#include "cgroup_test.h"
#include "namespace_probe.h"
#include "bootstrap_probe.h"
int main(int argc,char **argv) {
    if(argc!=2 || (strcmp(argv[1],"--diagnose") && strcmp(argv[1],"--check-host") && strcmp(argv[1],"--diagnose-json") && strcmp(argv[1],"--test-cgroup") && strcmp(argv[1],"--test-isolation") && strcmp(argv[1],"--test-bootstrap") && strcmp(argv[1],"--test-rootfs") && strcmp(argv[1],"--test-guard"))) {
        fputs("PD2425_HANDOFF_UNAVAILABLE: only --diagnose / --check-host / --diagnose-json / --test-cgroup / --test-isolation / --test-bootstrap / --test-rootfs / --test-guard; no changes made\n",stderr);
        return 78;
    }
    char device[PROP_VALUE_MAX],sdk[PROP_VALUE_MAX],abi[PROP_VALUE_MAX],fp[PROP_VALUE_MAX];
    __system_property_get("ro.product.device",device);
    __system_property_get("ro.build.version.sdk",sdk);
    __system_property_get("ro.product.cpu.abi",abi);
    __system_property_get("ro.build.fingerprint",fp);
    int matched=pd2425_identity(device,sdk,abi,fp);
    if(!strcmp(argv[1],"--test-cgroup"))return pd_cgroup_selftest_json(matched,fp);
    if(!strcmp(argv[1],"--test-guard"))return pd_boot_selftest_json(matched,fp,1,1);
    if(!strcmp(argv[1],"--test-rootfs"))return pd_boot_selftest_json(matched,fp,1,0);
    if(!strcmp(argv[1],"--test-bootstrap"))return pd_boot_selftest_json(matched,fp,0,0);
    if(!strcmp(argv[1],"--test-isolation"))return pd_namespace_selftest_json(matched,fp);
    if(!strcmp(argv[1],"--diagnose-json")){pd2425_json_report(matched,device,sdk,abi,fp);return matched?0:31;}
    printf("component=%s\ndevice=%s\nsdk=%s\nabi=%s\nfingerprint=%s\nhost_profile_match=%d\nota_identity_match=%d\n",COMPONENT,device,sdk,abi,fp,matched,matched&&!strcmp(fp,PD2425_FINGERPRINT));
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
