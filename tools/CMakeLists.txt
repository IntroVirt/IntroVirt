CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

FIND_PACKAGE(Boost REQUIRED COMPONENTS program_options)

INCLUDE_DIRECTORIES( BEFORE SYSTEM "${PROJECT_SOURCE_DIR}/include" )

# We're overriding ADD_EXECUTABLE here to create our own version that does some extra stuff, like deps and linking
FUNCTION(ADD_TOOL_EXECUTABLE EXE_NAME )
    ADD_EXECUTABLE(${EXE_NAME} ${ARGN})

    # I only have confidence in LTO on gcc-9.1+
    IF (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        IF (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            IF (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 9.1)
                MESSAGE(STATUS "Enabling link-time optimizations for ${EXE_NAME}")
                SET_PROPERTY(TARGET ${EXE_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
            ENDIF()
        ENDIF()
    ENDIF()

    INSTALL(
        TARGETS ${EXE_NAME} RUNTIME
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                    GROUP_READ GROUP_EXECUTE
        SETUID
        DESTINATION bin COMPONENT introvirt-tools)

    TARGET_LINK_LIBRARIES(${EXE_NAME} introvirt ${Boost_LIBRARIES} pthread)

ENDFUNCTION()

ADD_TOOL_EXECUTABLE(ivcallmon "ivcallmon.cc")
ADD_TOOL_EXECUTABLE(ivcr3mon "ivcr3mon.cc")
ADD_TOOL_EXECUTABLE(ivexec "ivexec.cc")
ADD_TOOL_EXECUTABLE(ivguestinfo "ivguestinfo.cc")
ADD_TOOL_EXECUTABLE(ivmemwatch "ivmemwatch.cc")
ADD_TOOL_EXECUTABLE(ivprocinfo "ivprocinfo.cc")
ADD_TOOL_EXECUTABLE(ivprocmemdump "ivprocmemdump.cc")
ADD_TOOL_EXECUTABLE(ivreadfile "ivreadfile.cc")
ADD_TOOL_EXECUTABLE(ivservicetable "ivservicetable.cc")
ADD_TOOL_EXECUTABLE(ivsessions "ivsessions.cc")
ADD_TOOL_EXECUTABLE(ivsyscallmon "ivsyscallmon.cc")
ADD_TOOL_EXECUTABLE(ivversion "ivversion.cc")
ADD_TOOL_EXECUTABLE(ivwritefile "ivwritefile.cc")
ADD_TOOL_EXECUTABLE(ivfilemon "ivfilemon.cc")
