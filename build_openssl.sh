#!/bin/bash

#NDK路径  修改成你自己的路径
ANDROID_NDK_ROOT=/home/you/ndk/android-ndk-r21d

#主机类型 macOS	darwin-x86_64  Linux linux-x86_64   32 位 Windows windows  64 位 Windows	windows-x86_64
ANDROID_HOST=linux-x86_64

#ABI类型 armeabi-v7a	  对应使用  armv7a-linux-androideabi   arm64-v8a	 对应使用  aarch64-linux-android  
#ABI类型 x86	i686-linux-android  x86_64	x86_64-linux-android
ANDROID_ABI=armeabi-v7a
ANDROID_TARGET=armv7a-linux-androideabi
#如果抛出编译c提示gnu/stubs-32.h:No such file or directory的解决方法 ubuntu： sudo apt-get install libc6-dev-i386 或者  CentOS：yum -y install glibc-devel.i686

#对应 arch-arm  arch-arm64  arch-x86  arch-x86_64
ANDROID_ARCH=arch-arm

#project minSdkVersion 根据你工程里的配置来高版本能兼容低版本
ANDROID_API=21

# armeabi-v7a  ->     -march=armv7-a -mfloat-abi=softfp -mfpu=neon           arm64-v8a     ->     -march=armv8-a
# x86          ->     -march=i386 -mtune=intel -mssse3 -mfpmath=sse -m32     x86-64        ->     -march=x86-64 -msse4.2 -mpopcnt -m64 -mtune=intel
#ANDROID_CFLAG="-march=armv7-a -mfloat-abi=softfp -mfpu=neon"

#生成安装的目录,一般第三方都会配置该参数
PREFIX=$(pwd)/android/$ANDROID_ABI

#--------------------------   以上是相关配置  --------------------------

#toolchain
ANDROID_TOOLCHAIN=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$ANDROID_HOST

#sysroot
ANDROID_SYSROOT=$ANDROID_NDK_ROOT/platforms/$ANDROID_API/$ANDROID_ARCH

export CC=$ANDROID_TOOLCHAIN/bin/$ANDROID_TARGET$ANDROID_API-clang
export RANLIB=$ANDROID_TOOLCHAIN/bin/llvm-ranlib


#export TOOLCHAIN=$ANDROID_TOOLCHAIN
#export SYSROOT="$ANDROID_SYSROOT"

#export TARGET=$ANDROID_TARGET
#export API=$ANDROID_API
#export AR=$ANDROID_TOOLCHAIN/bin/llvm-ar
#export CC=$ANDROID_TOOLCHAIN/bin/$ANDROID_TARGET$ANDROID_API-clang
#export AS=$CC
#export CXX=$ANDROID_TOOLCHAIN/bin/$ANDROID_TARGET$ANDROID_API-clang++
#export LD=$ANDROID_TOOLCHAIN/bin/ld
#export RANLIB=$ANDROID_TOOLCHAIN/bin/llvm-ranlib
#export STRIP=$ANDROID_TOOLCHAIN/bin/llvm-strip

#添加编译脚本方法  sleep 3秒 初次./config时有个延时
build()
{
	./config no-asm no-shared no-threads no-zlib no-zlib-dynamic no-hw no-dso no-egd no-engine \
	--openssldir=$(pwd)/android/$ANDROID_ABI \
	--prefix=$(pwd)/android/$ANDROID_ABI \
	
	sleep 3
	echo "start...."
	make clean
	make -j4
	make install
	echo "over...."
}
build