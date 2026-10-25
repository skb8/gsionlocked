import dev.tempgsi.controller.HostIdentity;
public class HostIdentityTest {
    public static void main(String[] args) {
        String fp=HostIdentity.PD2425_FINGERPRINT;
        if(!HostIdentity.matchesPd2425("PD2425",36,"arm64-v8a",HostIdentity.PD2425_FINGERPRINT_V000L1)||HostIdentity.matchesOtaFingerprint(HostIdentity.PD2425_FINGERPRINT_V000L1))throw new AssertionError();
        if(HostIdentity.matchesPd2425("PD2425",36,"arm64-v8a",HostIdentity.PD2425_FINGERPRINT_V000L1.replace("V000L1","V000L2")))throw new AssertionError();
        if(!HostIdentity.matchesPd2425("PD2425",36,"arm64-v8a",fp))throw new AssertionError();
        if(HostIdentity.matchesPd2425("PD2425B",36,"arm64-v8a",fp) ||
           HostIdentity.matchesPd2425("PD2425",35,"arm64-v8a",fp) ||
           HostIdentity.matchesPd2425("PD2425",36,"armeabi-v7a",fp) ||
           HostIdentity.matchesPd2425("PD2425",36,"arm64-v8a",fp+"new") ||
           HostIdentity.matchesPd2425(null,36,"arm64-v8a",null))throw new AssertionError();
        System.out.println("PASS: exact OTA identity required");
    }
}
