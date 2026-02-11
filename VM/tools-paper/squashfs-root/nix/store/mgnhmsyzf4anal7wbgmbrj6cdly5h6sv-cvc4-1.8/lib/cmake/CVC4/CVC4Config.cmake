
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was CVC4Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

set(CVC4_BINDINGS_JAVA OFF)
set(CVC4_BINDINGS_PYTHON OFF)

if(NOT TARGET CVC4::cvc4)
  include(${CMAKE_CURRENT_LIST_DIR}/CVC4Targets.cmake)
endif()

if(CVC4_BINDINGS_JAVA AND NOT TARGET CVC4::cvc4jar)
  set_and_check(CVC4_JNI_PATH "${PACKAGE_PREFIX_DIR}/lib")
  include(${CMAKE_CURRENT_LIST_DIR}/CVC4JavaTargets.cmake)
endif()
