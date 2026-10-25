# PD2425 diagnostic port

OTA-analyzed; host identities, own-child cgroup.kill and root-only mount/network/BinderFS probe tested on PD2425. **Not a runnable GSI environment.**
The preflight executables accept --check-host / --diagnose / --diagnose-json and explicit --test-cgroup / --test-isolation / --test-bootstrap / --test-rootfs / --test-guard.
For observation modes exit 0 means an exact allowlisted host identity, never readiness; exit 31 means mismatch;
78 rejects unsupported operations. Reports always contain runtime_ready=0.
Observation modes do not write. Observation modes never mount, control host services, change SELinux or open watchdog devices. The explicit cgroup test only creates/migrates/kills its own two children in a fresh group and removes it. The separate --test-isolation mode mounts tmpfs/BinderFS only inside those children's private mount namespaces.

Samsung loader, guardian and Java entry have early host gates. Never install
Samsung's prepared profile or adapters on Vivo. No Vivo blobs or device data
are included. See [the analysis and instructions](../../docs/PD2425.ru.md).

Schema-2 JSON observes process credentials, init PID or explicit executable
candidates, input key capabilities and watchdog metadata. No fd adoption,
event stream reading or service control is performed. APK 0.1.4 embeds the probe
and lets the owner save a root report. Review it with tools/review_pd2425.py;
its result always keeps runtime_ready=false.

Schema 3 separates host_profile_match (two exact fingerprints) from
ota_identity_match (original OTA fingerprint only). Observed identities preserve
primary GID separately from supplementary groups. Named GPIO/PMIC return keys
exclude headset devices. None of these observations enables guest launch.

--test-cgroup requires UID 0, Enforcing, a matching host and cgroup2. It returns
0 for a successful own-child test, 40 for test failure and 31 for host mismatch.
It does not require resource controllers, never migrates the caller/host PIDs,
and never uses group kill for failure cleanup. APK 0.1.5 can export a combined
snapshot/self-test report. See docs for temporary-group cleanup and limits.


APK 0.1.6 adds an explicit **namespace/BinderFS test**, not a guest launcher.
--test-isolation requires the same exact host, root, Enforcing and cgroup2.
Both children wait until pidfds and exact cgroup membership are verified.
They unshare mount/network namespaces, make mount propagation private, mount
private tmpfs/BinderFS and create three independent Binder devices each. Only
these private devices are opened (BINDER_VERSION); no stock Binder transaction
or service registration is attempted. Parent namespaces, stock device identities
and parent-visible directories are checked while children remain alive. The
normal cgroup.kill/drain/reap/remove path then destroys the test environment.
The deadline is 20 seconds. Failure cleanup targets only owned child processes;
there is no parent unmount, recursive removal, SELinux change or service control.
JSON reports partial stages and cleanup errors; a failed test is not readiness.

The owner's 0.1.5 report passed the cgroup test on 6.1.145 with KSU context and
SELinux Enforcing. This validates own-child cleanup only. The 0.1.7 BinderFS test also passed on the owner's phone. It does not validate PID/rootfs/BPF/SELinux isolation,
service-manager startup, hardware handoff, watchdog recovery or full GSI boot.


0.1.6 on-device result: mount/network namespaces and private BinderFS/control
succeeded, but BINDER_CTL_ADD returned EEXIST for both children. No Binder
protocol test or parent-preservation check completed; own-child cleanup passed.
0.1.7 supports standard nodes populated at mount by Android common kernels.
The control FD must have BINDERFS_SUPER_MAGIC; every node must be a non-symlink
character device on the same filesystem, independent from all stock/peer nodes.
Missing nodes use BINDER_CTL_ADD and returned IDs must match. Opened FD identity
must match lstat before BINDER_VERSION. Unexpected EEXIST is still an error.
JSON records binderfs_verified and allocation; devices_created counts validated
nodes, whether mount-created or ioctl-created. Parent preservation is checked
after both reports even on worker failure. No launch condition is bypassed.


The owner's subsequent 0.1.7 report passed: six distinct mount-created private
Binder nodes, protocol 8, two distinct mount/network namespaces, unchanged parent
namespace/device/directory observations, cgroup.kill, drain, reap and cleanup.
The profile stores only sanitized facts and the source report SHA-256, never
PIDs, namespace inode numbers, boot IDs or the raw report. Repeating this probe
is not required for this same setup. This is not a guest boot or a host handoff.
The reviewer accepts a self-test proof only with the outer exact host, UID 0 and
SELinux Enforcing observations as well as the complete nested result.


0.1.8 adds --test-bootstrap: two direct CLONE_NEWPID children, each inert PID 1,
with private read-only tmpfs root and private read-only proc. No grandchildren,
Android init, imported GSI or shell executes. Bionic's fork-like clone wrapper
maintains libc pid/tid caches; an inherited owner pidfd protects the parent-death
race when getppid is zero. Both children wait for cgroup ownership verification.
All inherited FDs except a write-only result pipe close before chroot. The test
verifies PID1/proc membership, filesystem type/flags, absence of host paths,
independent namespaces/roots and unchanged parent observations. Deadline: 25 s.
A second exact-membership check precedes group kill in every explicit test.
Failure cleanup never group-kills a changed group, only unreaped owned children.
The inert scaffold is device-unvalidated and is not an untrusted-code sandbox.
No launch authorization or hardware handoff is provided. See the Russian guide.


0.1.8 phone result: stat /proc/self/ns/pid returned ENOENT before any group or
child creation. PID namespace support is not established (CONFIG_PID_NS=n is
consistent with this but not proven). 0.1.9 reports the exact setup stage and
read-only namespace-entry availability. Strict --test-bootstrap still refuses.
The original Samsung loader uses a shared PID namespace, so PID1 was an extra
experiment rather than its mandatory architecture. A shared-PID guest still
requires the original signal/seccomp/BPF and filesystem protections.

The separate --test-rootfs uses two ordinary owned children, private read-only
tmpfs/chroot and FD closure. It never mounts proc and verifies /proc is absent.
It has a separate rootfs-self-test contract with pid_namespace_required=false
and proc_required=false. Its success cannot validate PID/proc/Binder isolation,
Android bootstrap or an untrusted-code sandbox. Device validation is pending.


The owner's 0.1.9 report passed rootfs-only isolation and complete own-child
cleanup. PID/proc/Binder or guest execution are not implied. Namespace entries
mnt/net/uts/cgroup were present; pid/pid_for_children/ipc/user returned ENOENT.

0.1.10 adds explicit --test-guard (guard-self-test) on the same inert rootfs
scaffold. Each trusted child installs no_new_privs and an arch-checked seccomp
deny list of 12 signal, ptrace, remote-memory, BPF and perf syscall paths.
Only harmless self signal=0, zero-length self memory I/O and invalid-argument
probes run. No host target, ptrace attach, perf event or BPF program is used.
Parent seccomp/no_new_privs and self signal permission must remain unchanged.
The filter is tested on the real CI kernel in an owned child; arm64 device
integration is pending. This limited union policy is not a complete sandbox or
an Android service policy (e.g. blanket tgkill denial may break Java). No guest
or host service is executed/controlled. All exact host/root/Enforcing and cleanup
gates remain in force; unsupported/failed setup never authorizes launch.


0.1.11 adds a separate pd2425-gsi-preview executable, packaged as
libpd2425_gsi.so. It pins an unmodified upstream EvoX Vanilla raw ext4 image and
runtime APEX, creates private mount/network namespaces, attaches read-only
AUTOCLEAR loops, then executes the GSI linker/mksh with UID/GID65534, zero caps,
no_new_privs, closed inherited FDs and a new default-deny seccomp allowlist.
Only a fixed printf command executes; no Android framework/HAL or host service
control. Time/resource/output bounds, owned pidfd termination, loop release and
parent namespace/root checks are required. --verify-image is read-only for host
preparation. --preview-gsi requires the exact PD2425 host/root/Enforcing/image.
See the detailed Russian guide and profiles/pd2425-evox-preview.json.
The owner accepts reboot recovery, so hot restore is deferred; source partition
and data protection remain mandatory. Physical takeover is still unavailable.
The previous syscall-guard test is now device-confirmed; real GSI preview is
implemented but device-unvalidated. No GSI/Vivo binaries are distributed.


Owner-device milestone: APK 0.1.16 successfully executed the exact upstream
GSI linker/libc/mksh builtin marker with capless UID65534, seccomp and complete
cleanup. See the sanitized observation/profile; this is not Android/HAL boot.
`tools/prepare_pd2425_apex.py` now prepares the pinned GSI's 36 APEX payloads
(26 CAPEX), plus direct ELF dependency metadata, offline without mounting or
executing image code. `profiles/pd2425-evox-apex.json` records the analyzed inputs.
Manifest name/version and CAPEX/original/payload consistency are now verified.
AVB signatures and transitive namespace compatibility remain unverified; no
full mount/launch authorization is emitted.


APK 0.1.17 adds `--preview-service-loader IMAGE`: a private readonly bootstrap
linkerconfig plus GSI linker64 `--list /system/bin/servicemanager`. This is a
loader test, not a running service manager. Existing capless/default-deny guards
and shell mode remain; native main/PID/Binder/HAL bootstrap stays gated.

`tools/analyze_pd2425_dependencies.py` now follows transitive candidate ELF
chains and audits strong symbol name/version availability. The compact source
summary records the 8/21/22/244 ELF graphs, ART provider separation and pending
unversioned fallback cases. Namespace/symbol binding, service main and HAL
compatibility remain explicitly unverified.
