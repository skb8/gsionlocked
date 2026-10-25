#ifndef GSIONLOCKED_PD2425_PROFILE_H
#define GSIONLOCKED_PD2425_PROFILE_H
#include <string.h>
#define PD2425_FINGERPRINT "vivo/PD2425/PD2425:16/BP2A.250605.031.A3/compiler260917174806:user/release-keys"
#define PD2425_FINGERPRINT_V000L1 "vivo/PD2425/PD2425:16/BP2A.250605.031.A3_V000L1/compiler260917174806:user/release-keys"
/* Exact observed host variants; neither identity authorizes handoff. */
static inline int pd2425_identity(const char *device,const char *sdk,const char *abi,const char *fingerprint) {
    return !strcmp(device,"PD2425") && !strcmp(sdk,"36") && !strcmp(abi,"arm64-v8a") && (!strcmp(fingerprint,PD2425_FINGERPRINT)||!strcmp(fingerprint,PD2425_FINGERPRINT_V000L1));
}
#endif
