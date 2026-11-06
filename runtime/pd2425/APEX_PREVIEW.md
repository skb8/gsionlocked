# PD2425: bounded APEX / ART / AndroidRuntime preview

This CLI advances the userspace port; it does not boot Android or take over the
screen. APK Start remains gated. The owner tested it through ADB on 2026-11-07.

It verifies the pinned GSI and all 36 extracted APEX payloads, mounts them read-only
in a private mount/network namespace, and runs the GSI's own linkerconfig and
class-path tools. It then runs a pinned Java probe twice: directly in dalvikvm64
and through app_process64 / AndroidRuntime. The probe verifies a real Java
thread, arithmetic, GC, a framework class and (in AndroidRuntime) the real
SELinux enabled/enforcing queries. A zero exit alone is insufficient: the
supervisor requires the Java marker from the owned output pipe or an
SCM_CREDENTIALS-authenticated System.out record of that specific PID.

The tested result has LINKERCONFIG_EXIT=0, APP_PROCESS_LOADER_EXIT=0,
DERIVE_CLASSPATH_EXIT=0, ART_MAIN_EXIT=0, APP_PROCESS_JAVA_EXIT=0 and
preview_passed=true. All 37 owned loops are released, the temporary directory is
removed, the parent mount/network/root and source image are unchanged, and host
Enforcing is preserved. System-server class paths are generated, not executed.

The Java children are UID/GID1000, capless, NNP, default-deny seccomp, with CPU,
file-size and wall limits. They retain the development KSU SELinux domain; this
is not proof of Zygote/system_server domains or production app isolation.
A hash-pinned constructor points each accessible libselinux namespace copy to
the genuine read-only selinuxfs and verifies enabled, Enforcing, readonly flags
and the actual development context. It uses the original libselinux APIs and
does not replace access checks, permission results, abort APIs or policy.

Only the owned proc subtree, a read-only filesystem list and own mount list are
exposed. Private Binder devices and a private log socket replace host IPC.
Firmware vendor/odm and VNDK34 are bound read-only/noexec for linker metadata;
this does not establish vendor HAL ABI or hardware compatibility. Guest data
is a bounded tmpfs. Changing scheduling priorities, creating guest processes,
Internet sockets, host signals and privileged setters remain denied. Private
thread creation, own-TGID signals, anonymous memory FDs and private memory
barriers support ART. Diagnostic plugin/niceness warnings can remain nonfatal.

## Build and prepare

Use the same Android SDK 35, NDK and JDK inputs as the normal build:

```sh
python tools/build_apex_preview.py --sdk "$ANDROID_HOME" --java-home "$JAVA_HOME" --ndk "$ANDROID_NDK_HOME"
python tools/prepare_pd2425_apex.py /private/selected.img --output /private/apex-inputs
```

`dist/pd2425-apex-preview/` contains the CLI, selinux-check.so, art-probe.jar and
build hashes. The prepared `.img` payloads and GSI are private external inputs;
they are not redistributed. Source catalogs and original-image hashes must
match. The input extractor does not provide AVB signature/attestation proof.

On the development phone the 36 payloads are already staged under
`/data/local/tmp/gsion-apex-payloads`. For a clean staging directory, copy only
the 36 generated payload `.img` files plus selinux-check.so and art-probe.jar.
As root, give payload files root ownership, mode 0400 and the genuine
`u:object_r:staging_data_file:s0` label; this label lets the kernel loop worker
read them under Enforcing. Do not relabel firmware or other existing files.
Then run the built CLI as root with these two arguments:

```sh
/data/local/tmp/gsion-apex-preview /data/user/0/dev.tempgsi.controller/files/gsi/selected.img /data/local/tmp/gsion-apex-payloads
```

The final JSON explicitly reports runtime_ready=false, guest_boot_complete=false,
display_handoff=false and touch_handoff=false. An APK-only update does not stage
these payloads or expose this developer CLI in the UI.

Next required work is a jointly supervised private service-manager/property
session, followed by Zygote/system_server, and then an independently recoverable
Vivo HAL / SurfaceFlinger / input handoff. Separate smoke tests do not authorize
hardware takeover. The existing PD2425 launch guard stays disabled.

Linker configuration inputs follow the
[AOSP linkerconfig interface](https://android.googlesource.com/platform/system/linkerconfig/)
and the
[AOSP APEX info schema](https://android.googlesource.com/platform/system/apex/+/master/apexd/ApexInfoList.xsd).
