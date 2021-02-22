CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

INCLUDE_DIRECTORIES( BEFORE SYSTEM "${PROJECT_SOURCE_DIR}/include" )

# We're overriding ADD_EXECUTABLE here to create our own version that does some extra stuff, like deps and linking
FUNCTION(ADD_EXAMPLE_EXECUTABLE EXE_NAME )
    ADD_EXECUTABLE(${EXE_NAME} ${ARGN})
    TARGET_LINK_LIBRARIES(${EXE_NAME} introvirt boost_program_options)
ENDFUNCTION()

ADD_EXAMPLE_EXECUTABLE(syscall_monitor "syscall_monitor.cc")
ADD_EXAMPLE_EXECUTABLE(vmcall_interface "vmcall_interface.cc")
