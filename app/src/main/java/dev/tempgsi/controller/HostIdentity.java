package dev.tempgsi.controller;
/** OTA identity is distinct from a validated, launchable runtime. */
public final class HostIdentity {
    public static final String PD2425_FINGERPRINT="vivo/PD2425/PD2425:16/BP2A.250605.031.A3/compiler260917174806:user/release-keys";
    public static boolean isPd2425(String device) { return "PD2425".equals(device); }
    public static boolean matchesPd2425(String device,int sdk,String abi,String fingerprint) {
        return isPd2425(device)&&sdk==36&&"arm64-v8a".equals(abi)&&PD2425_FINGERPRINT.equals(fingerprint);
    }
    private HostIdentity() {}
}
