/* Read-only identity gate; call before argument-dependent side effects. */
#ifndef GSIONLOCKED_HOST_GUARD_H
#define GSIONLOCKED_HOST_GUARD_H
#include <sys/system_properties.h>
#include <stdio.h>
#include <string.h>
static int require_dm1q_host(void) {
    char model[PROP_VALUE_MAX],device[PROP_VALUE_MAX],sdk[PROP_VALUE_MAX],firmware[PROP_VALUE_MAX];
    __system_property_get("ro.product.model",model);
    __system_property_get("ro.product.device",device);
    __system_property_get("ro.build.version.sdk",sdk);
    __system_property_get("ro.bootloader",firmware);
    if(strcmp(model,"SM-S911B") || strcmp(device,"dm1q") || strcmp(sdk,"36") || strcmp(firmware,"S911BXXSAFZG1")) {
        fputs("REFUSE_DM1Q_HOST_MISMATCH_NO_CHANGES; PD2425 requires its own runtime\n",stderr);
        return 31;
    }
    return 0;
}
#endif
