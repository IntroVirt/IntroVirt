cmake_minimum_required(VERSION 3.14)

if(NOT DEFINED SOURCE_DIR)
  message(FATAL_ERROR "SOURCE_DIR is required")
endif()
if(NOT DEFINED BINARY_DIR)
  message(FATAL_ERROR "BINARY_DIR is required")
endif()
if(NOT DEFINED PYTHON_OUTDIR)
  message(FATAL_ERROR "PYTHON_OUTDIR is required")
endif()
if(NOT DEFINED UV_EXECUTABLE)
  message(FATAL_ERROR "UV_EXECUTABLE is required")
endif()

set(STAGE_DIR "${BINARY_DIR}/python/pyintrovirt_stage")
set(DIST_DIR "${BINARY_DIR}/python/dist")

file(MAKE_DIRECTORY "${STAGE_DIR}")
file(MAKE_DIRECTORY "${DIST_DIR}")

# Stage the pyintrovirt project (avoid copying local dev artifacts).
file(COPY "${SOURCE_DIR}/pyintrovirt/"
  DESTINATION "${STAGE_DIR}"
  PATTERN ".venv" EXCLUDE
  PATTERN "dist" EXCLUDE
  PATTERN "__pycache__" EXCLUDE
  PATTERN ".pytest_cache" EXCLUDE
)

# Copy the SWIG-generated bindings into the wheel root so `import introvirt` works.
foreach(f IN ITEMS "introvirt.py" "introvirt.pyi")
  if(NOT EXISTS "${PYTHON_OUTDIR}/${f}")
    message(FATAL_ERROR "Missing required SWIG artifact: ${PYTHON_OUTDIR}/${f}")
  endif()
  file(COPY_FILE "${PYTHON_OUTDIR}/${f}" "${STAGE_DIR}/${f}")
endforeach()

file(GLOB introvirt_ext "${PYTHON_OUTDIR}/_introvirt_py*.so")
list(LENGTH introvirt_ext introvirt_ext_count)
if(introvirt_ext_count LESS 1)
  message(FATAL_ERROR "Missing SWIG extension module: ${PYTHON_OUTDIR}/_introvirt_py*.so")
endif()
foreach(ext IN LISTS introvirt_ext)
  get_filename_component(ext_name "${ext}" NAME)
  file(COPY_FILE "${ext}" "${STAGE_DIR}/${ext_name}")
endforeach()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env
    HATCH_BUILD_HOOKS_ENABLE=1
    "${UV_EXECUTABLE}" build --directory "${STAGE_DIR}" --out-dir "${DIST_DIR}"
  RESULT_VARIABLE uv_rc
)
if(NOT uv_rc EQUAL 0)
  message(FATAL_ERROR "uv build failed with exit code ${uv_rc}")
endif()

