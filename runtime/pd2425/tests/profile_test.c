#include <assert.h>
#include <stdio.h>
#include "profile.h"
int main(void) {
    assert(pd2425_identity("PD2425","36","arm64-v8a",PD2425_FINGERPRINT));
    assert(pd2425_identity("PD2425","36","arm64-v8a",PD2425_FINGERPRINT_V000L1));
    assert(!pd2425_identity("PD2425","36","arm64-v8a","vivo/PD2425/PD2425:16/BP2A.250605.031.A3_V000L2/compiler260917174806:user/release-keys"));
    assert(!pd2425_identity("PD2425B","36","arm64-v8a",PD2425_FINGERPRINT));
    assert(!pd2425_identity("PD2425","35","arm64-v8a",PD2425_FINGERPRINT));
    assert(!pd2425_identity("PD2425","36","armeabi-v7a",PD2425_FINGERPRINT));
    assert(!pd2425_identity("PD2425","36","arm64-v8a","new-firmware"));
    assert(!pd2425_identity("dm1q","36","arm64-v8a",PD2425_FINGERPRINT));
    puts("PASS: PD2425 identity positive and negative cases");
}
