#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "libzmq" for configuration "Release"
set_property(TARGET libzmq APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libzmq PROPERTIES
  IMPORTED_LOCATION_RELEASE "/nix/store/6k7nznrdf3qy0bi7d26r4dcidyi8gaz2-zeromq-4.3.3/lib/libzmq.so.5.2.3"
  IMPORTED_SONAME_RELEASE "libzmq.so.5"
  )

list(APPEND _IMPORT_CHECK_TARGETS libzmq )
list(APPEND _IMPORT_CHECK_FILES_FOR_libzmq "/nix/store/6k7nznrdf3qy0bi7d26r4dcidyi8gaz2-zeromq-4.3.3/lib/libzmq.so.5.2.3" )

# Import target "libzmq-static" for configuration "Release"
set_property(TARGET libzmq-static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libzmq-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C;CXX"
  IMPORTED_LOCATION_RELEASE "/nix/store/6k7nznrdf3qy0bi7d26r4dcidyi8gaz2-zeromq-4.3.3/lib/libzmq.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS libzmq-static )
list(APPEND _IMPORT_CHECK_FILES_FOR_libzmq-static "/nix/store/6k7nznrdf3qy0bi7d26r4dcidyi8gaz2-zeromq-4.3.3/lib/libzmq.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
