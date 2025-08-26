@echo off
set MACOS_SDK=C:\Users\debas\Downloads\sdk-macos-12.0-main\sdk\root
zig cc --sysroot %MACOS_SDK% -L%MACOS_SDK%\usr\lib -I%MACOS_SDK%\usr\include -F%MACOS_SDK%\System\Library\Frameworks -framework CoreFoundation -framework Security -target aarch64-macos-none %*