# PD2425 diagnostic port

OTA-analyzed; host identities and own-child cgroup.kill tested on PD2425. **Not a runnable GSI environment.**
The preflight executables accept --check-host / --diagnose / --diagnose-json and an explicit --test-cgroup.
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
SELinux Enforcing. This validates own-child cleanup only. The new BinderFS test
still needs a phone run. It does not validate PID/rootfs/BPF/SELinux isolation,
service-manager startup, hardware handoff, watchdog recovery or full GSI boot.
