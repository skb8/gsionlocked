package dev.tempgsi.controller;

import android.os.Build;
import java.io.IOException;

/** Only hardware/firmware combinations tested with this runtime may launch. */
final class DeviceProfile {
    static final String SHA256="5e8333e15798592bae059bcb78ba85394418afc8f035a13fc0e97c086b8c1e49";
    static final long IMAGE_BYTES=3863474176L;
    static final String SOURCE="/data/local/tmp/tempgsi-evox154/system.img";
    static void requireHost() throws IOException {
        if(HostIdentity.isPd2425(Build.DEVICE))
            throw new IOException("PD2425: диагностический порт. Запуск GSI заблокирован: ещё не проверены Vivo HAL, дисплей/ввод, watchdog и восстановление OriginOS. Откройте диагностику PD2425.");
        if(!"SM-S911B".equals(Build.MODEL)||Build.VERSION.SDK_INT!=36||!Build.FINGERPRINT.contains("/dm1q")||!Build.FINGERPRINT.contains("S911BXXSAFZG1"))
            throw new IOException("No tested runtime profile for "+Build.MODEL+" / "+Build.DISPLAY+". Supported: SM-S911B, OneUI S911BXXSAFZG1.");
    }
    private DeviceProfile(){}
}
