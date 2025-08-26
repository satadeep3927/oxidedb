@echo off
set args=%*
set args=%args:--target=arm64-apple-macosx=--target=aarch64-macos%
set args=%args:--target=x86_64-apple-macosx=--target=x86_64-macos%
set args=%args:-target aarch64-apple-darwin=-target aarch64-macos%
set args=%args:-target x86_64-apple-darwin=-target x86_64-macos%
zig cc %args%
