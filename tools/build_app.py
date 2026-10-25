"""Build with Android SDK/NDK and JDK 17; no workspace-specific paths."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, sys, zipfile

from pd2425_build import generate_services

ROOT = Path(__file__).resolve().parents[1]

def run(*args):
    subprocess.run([str(a) for a in args], check=True, timeout=180)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', default=os.getenv('ANDROID_SDK_ROOT') or os.getenv('ANDROID_HOME'))
    parser.add_argument('--ndk', default=os.getenv('ANDROID_NDK_HOME'))
    parser.add_argument('--java-home', default=os.getenv('JAVA_HOME'))
    parser.add_argument('--debug', action='store_true', help='Sign with an ignored local development key')
    parser.add_argument('--keystore', type=Path, help='External release key, never copied into this repository')
    parser.add_argument('--alias', default='gsionlocked')
    parser.add_argument('--root-client-apk', type=Path, help='Optional official KernelSU 3.2.5 APK; see THIRD_PARTY.md')
    args = parser.parse_args()
    if not args.sdk or not args.java_home:
        parser.error('Set ANDROID_HOME and JAVA_HOME, or pass --sdk and --java-home.')
    if args.debug and args.keystore:
        parser.error('Use either --debug or --keystore.')
    sdk = Path(args.sdk).resolve(); java = Path(args.java_home).resolve() / 'bin'
    ndk = Path(args.ndk).resolve() if args.ndk else sdk / 'ndk/25.2.9519653'
    host = 'windows-x86_64' if os.name == 'nt' else ('darwin-x86_64' if sys.platform == 'darwin' else 'linux-x86_64')
    exe = '.exe' if os.name == 'nt' else ''
    clang = ndk / f'toolchains/llvm/prebuilt/{host}/bin/clang{exe}'
    tools = sdk / 'build-tools/35.0.0'; android = sdk / 'platforms/android-35/android.jar'
    for required in [clang, android, java / ('javac'+exe), tools / ('aapt'+exe)]:
        if not required.is_file():
            parser.error(f'Missing tool: {required}')
    build = ROOT / 'build/app'
    if build.exists():
        if not build.resolve().is_relative_to(ROOT / 'build'):
            raise RuntimeError('Unexpected build path')
        shutil.rmtree(build)
    for name in ['classes', 'dex', 'assets']:
        (build/name).mkdir(parents=True, exist_ok=True)
    src = ROOT / 'app/src/main'
    run(clang, '--target=aarch64-linux-android33', '-fuse-ld=lld', '-static', '-O2', '-Wall', '-Wextra', '-Werror', src/'session_launch.c', '-o', build/'assets/session-launch')
    probe_include=generate_services(build/'probe-include')
    run(clang, '--target=aarch64-linux-android33', '-fuse-ld=lld', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-DCOMPONENT="apk-probe"', '-I', ROOT/'runtime/pd2425/include', '-I', probe_include, ROOT/'runtime/pd2425/src/preflight.c', '-o', build/'libpd2425_probe.so')
    run(clang, '--target=aarch64-linux-android33', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror', ROOT/'runtime/pd2425/src/service_check.c', '-ldl', '-o', build/'libpd2425_sm_check.so')
    helper = build/'libpd2425_sm_check.so'
    helper_pin = ['-DPD_SM_CHECK_SHA="'+hashlib.sha256(helper.read_bytes()).hexdigest()+'"', '-DPD_SM_CHECK_BYTES='+str(helper.stat().st_size)]
    run(clang, '--target=aarch64-linux-android33', '-fuse-ld=lld', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-DCOMPONENT="apk-gsi-preview"', *helper_pin, '-I', ROOT/'runtime/pd2425/include', '-I', probe_include, ROOT/'runtime/pd2425/src/gsi_preview.c', '-o', build/'libpd2425_gsi.so')
    run(java/('javac'+exe), '-encoding', 'UTF-8', '-source', '8', '-target', '8', '-cp', android, '-d', build/'classes', *sorted((src/'java').rglob('*.java')))
    run(java/('java'+exe), '-cp', tools/'lib/d8.jar', 'com.android.tools.r8.D8', '--min-api', '31', '--lib', android, '--output', build/'dex', *sorted((build/'classes').rglob('*.class')))
    run(tools/('aapt'+exe), 'package', '-f', '-M', src/'AndroidManifest.xml', '-S', src/'res', '-A', build/'assets', '-I', android, '-F', build/'unsigned.apk')
    with zipfile.ZipFile(build/'unsigned.apk', 'a') as apk:
        apk.write(build/'dex/classes.dex', 'classes.dex')
        apk.write(build/'libpd2425_probe.so', 'lib/arm64-v8a/libpd2425_probe.so')
        apk.write(build/'libpd2425_gsi.so', 'lib/arm64-v8a/libpd2425_gsi.so')
        apk.write(build/'libpd2425_sm_check.so', 'lib/arm64-v8a/libpd2425_sm_check.so')
        if args.root_client_apk:
            digest = hashlib.sha256(args.root_client_apk.read_bytes()).hexdigest()
            if digest != '1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916':
                raise RuntimeError('Root client is not the pinned official KernelSU APK')
            with zipfile.ZipFile(args.root_client_apk) as official:
                apk.writestr('lib/arm64-v8a/libksud.so', official.read('lib/arm64-v8a/libksud.so'))
            apk.write(ROOT/'THIRD_PARTY.md', 'assets/THIRD_PARTY.md')
            apk.write(ROOT/'licenses/KernelSU-GPL-3.0.txt', 'assets/KernelSU-GPL-3.0.txt')
    run(tools/('zipalign'+exe), '-f', '4', build/'unsigned.apk', build/'aligned.apk')
    dist = ROOT / 'dist'; dist.mkdir(exist_ok=True)
    output = dist / 'gsionlocked-unsigned.apk'
    if args.debug or args.keystore:
        key = args.keystore.resolve() if args.keystore else ROOT/'build/debug.keystore'
        alias = args.alias if args.keystore else 'androiddebugkey'
        if args.debug and not key.exists():
            run(java/('keytool'+exe), '-genkeypair', '-keystore', key, '-alias', alias, '-storepass', 'android', '-keypass', 'android', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '3650', '-dname', 'CN=Android Debug,O=Android,C=US')
        if args.debug:
            os.environ['GSIONLOCKED_STORE_PASS'] = 'android'; os.environ['GSIONLOCKED_KEY_PASS'] = 'android'
        if not os.getenv('GSIONLOCKED_STORE_PASS') or not os.getenv('GSIONLOCKED_KEY_PASS'):
            parser.error('Set GSIONLOCKED_STORE_PASS and GSIONLOCKED_KEY_PASS in your environment.')
        output = dist/'gsionlocked.apk'
        run(java/('java'+exe), '-jar', tools/'lib/apksigner.jar', 'sign', '--ks', key, '--ks-key-alias', alias, '--ks-pass', 'env:GSIONLOCKED_STORE_PASS', '--key-pass', 'env:GSIONLOCKED_KEY_PASS', '--out', output, build/'aligned.apk')
        run(java/('java'+exe), '-jar', tools/'lib/apksigner.jar', 'verify', '--verbose', output)
    else:
        shutil.copy2(build/'aligned.apk', output)
    (dist/'build.json').write_text(json.dumps({'file':output.name,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'signed':args.debug or args.keystore is not None,'bundled_root_client':bool(args.root_client_apk)}, indent=2)+'\n')
    print(output)

if __name__ == '__main__':
    main()
