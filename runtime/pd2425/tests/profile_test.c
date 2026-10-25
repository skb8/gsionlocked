#include <assert.h>
#include <stdio.h>
#include "profile.h"
int main(void) {
    assert(pd2425_identity("PD2425","36","arm64-v8a",PD2425_FINGERPRINT));
    assert(!pd2425_identity("PD2425B","36","arm64-v8a",PD2425_FINGERPRINT));
    assert(!pd2425_identity("PD2425","35","arm64-v8a",PD2425_FINGERPRINT));
    assert(!pd2425_identity("PD2425","36","armeabi-v7a",PD2425_FINGERPRINT));
    assert(!pd2425_identity("PD2425","36","arm64-v8a","new-firmware"));
    assert(!pd2425_identity("dm1q","36","arm64-v8a",PD2425_FINGERPRINT));
    puts("PASS: PD2425 identity positive and negative cases");
}
