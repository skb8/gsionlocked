# PD2425 diagnostic port

OTA-analyzed, device-unvalidated. **Not a runnable GSI environment.**
The two preflight executables accept only --check-host / --diagnose / --diagnose-json.
Exit 0 means exact OTA identity, never readiness; exit 31 means mismatch;
78 rejects unsupported operations. Reports always contain runtime_ready=0.
They do not mount, control services, change SELinux or open watchdog devices.

Samsung loader, guardian and Java entry have early host gates. Never install
Samsung's prepared profile or adapters on Vivo. No Vivo blobs or device data
are included. See [the analysis and instructions](../../docs/PD2425.ru.md).

Schema-2 JSON observes process credentials, init PID or explicit executable
candidates, input key capabilities and watchdog metadata. No fd adoption,
event stream reading or service control is performed. APK 0.1.4 embeds the probe
and lets the owner save a root report. Review it with tools/review_pd2425.py;
its result always keeps runtime_ready=false.
