#set(CMAKE_SYSTEM_NAME Arm)
#this one not so much
#set(CMAKE_SYSTEM_VERSION 1)

# specify the cross compiler
set(CMAKE_C_COMPILER   arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_AR arm-none-eabi-ar CACHE FILEPATH "Archiver")

# where is the target environment 
set(CMAKE_FIND_ROOT_PATH  /usr/lib/arm-none-eabi/)

# search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")
