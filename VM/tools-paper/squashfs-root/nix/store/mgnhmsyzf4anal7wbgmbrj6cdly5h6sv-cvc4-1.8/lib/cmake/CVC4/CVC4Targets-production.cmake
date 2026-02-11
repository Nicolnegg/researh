#----------------------------------------------------------------
# Generated CMake target import file for configuration "Production".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "CVC4::cvc4parser" for configuration "Production"
set_property(TARGET CVC4::cvc4parser APPEND PROPERTY IMPORTED_CONFIGURATIONS PRODUCTION)
set_target_properties(CVC4::cvc4parser PROPERTIES
  IMPORTED_LOCATION_PRODUCTION "${_IMPORT_PREFIX}/lib/libcvc4parser.so.7"
  IMPORTED_SONAME_PRODUCTION "libcvc4parser.so.7"
  )

list(APPEND _IMPORT_CHECK_TARGETS CVC4::cvc4parser )
list(APPEND _IMPORT_CHECK_FILES_FOR_CVC4::cvc4parser "${_IMPORT_PREFIX}/lib/libcvc4parser.so.7" )

# Import target "CVC4::cvc4" for configuration "Production"
set_property(TARGET CVC4::cvc4 APPEND PROPERTY IMPORTED_CONFIGURATIONS PRODUCTION)
set_target_properties(CVC4::cvc4 PROPERTIES
  IMPORTED_LOCATION_PRODUCTION "${_IMPORT_PREFIX}/lib/libcvc4.so.7"
  IMPORTED_SONAME_PRODUCTION "libcvc4.so.7"
  )

list(APPEND _IMPORT_CHECK_TARGETS CVC4::cvc4 )
list(APPEND _IMPORT_CHECK_FILES_FOR_CVC4::cvc4 "${_IMPORT_PREFIX}/lib/libcvc4.so.7" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
