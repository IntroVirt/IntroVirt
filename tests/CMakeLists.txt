CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

INCLUDE_DIRECTORIES( BEFORE SYSTEM "${PROJECT_SOURCE_DIR}/include" )

# We're overriding ADD_EXECUTABLE here to create our own version that does some extra stuff, like deps and linking
FUNCTION(ADD_EXAMPLE_EXECUTABLE EXE_NAME )
    ADD_EXECUTABLE(${EXE_NAME} ${ARGN})
    TARGET_LINK_LIBRARIES(${EXE_NAME} introvirt)
ENDFUNCTION()

ADD_EXAMPLE_EXECUTABLE(gdt "gdt.cc")
ADD_EXAMPLE_EXECUTABLE(idt "idt.cc")
ADD_EXAMPLE_EXECUTABLE(readmem "readmem.cc")
ADD_EXAMPLE_EXECUTABLE(readvcpu "readvcpu.cc")

ADD_EXAMPLE_EXECUTABLE(linux_profile "linux_profile.cc")
TARGET_COMPILE_DEFINITIONS(linux_profile PRIVATE
    LINUX_PROFILE_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/fixtures/linux-profile-ok.json")
ADD_TEST(NAME linux_profile COMMAND linux_profile)
