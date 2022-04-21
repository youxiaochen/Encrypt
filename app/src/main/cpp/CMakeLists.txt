# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os -Wall -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os -Wall -s")

#include头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include)

# 指定链接库文件目录
link_directories(${PROJECT_SOURCE_DIR}/jniLibs/${ANDROID_ABI})

file(GLOB SRC_CPP_LIST ${PROJECT_SOURCE_DIR}/*.cpp)


add_library( # Sets the name of the library.
        encrypt

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        ${SRC_CPP_LIST} )

target_link_libraries( # Specifies the target library.
        encrypt
        log
        crypto
        ssl)