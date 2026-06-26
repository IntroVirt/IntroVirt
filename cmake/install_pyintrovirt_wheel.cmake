# Install pyintrovirt wheel into Debian system site-packages (invoked from install(CODE)).
# Expects PYINTROVIRT_DIST_DIR and PYINTROVIRT_PYTHON to be set by the caller.

if(NOT DEFINED PYINTROVIRT_DIST_DIR)
  message(FATAL_ERROR "PYINTROVIRT_DIST_DIR is not set")
endif()
if(NOT DEFINED PYINTROVIRT_PYTHON)
  message(FATAL_ERROR "PYINTROVIRT_PYTHON is not set")
endif()

set(_destdir "")
if(DEFINED ENV{DESTDIR})
  set(_destdir "$ENV{DESTDIR}")
endif()

execute_process(
  COMMAND "${PYINTROVIRT_PYTHON}"
    "${CMAKE_CURRENT_LIST_DIR}/install_pyintrovirt_wheel.py"
    --dist-dir "${PYINTROVIRT_DIST_DIR}"
    --destdir "${_destdir}"
  RESULT_VARIABLE _install_rc
  ERROR_VARIABLE _install_err
  OUTPUT_VARIABLE _install_out
)
if(NOT _install_rc EQUAL 0)
  message(FATAL_ERROR
    "Failed to install pyintrovirt wheel from ${PYINTROVIRT_DIST_DIR} with exit code ${_install_rc}: ${_install_err}${_install_out}")
endif()
