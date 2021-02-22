find_package(Git)
if(GIT_FOUND)
        # Try to get the commit based on the most recent tag
        execute_process(COMMAND ${GIT_EXECUTABLE} describe --tags --dirty RESULT_VARIABLE res_var OUTPUT_VARIABLE GIT_COM_ID )

        if( NOT ${res_var} EQUAL 0 )
            # Try again to just get the commit hash
            execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD RESULT_VARIABLE res_var OUTPUT_VARIABLE GIT_COM_ID )
        endif()

        if( ${res_var} EQUAL 0 )
            # Remove trailing newline
            string( REPLACE "\n" "" GIT_COMMIT_ID ${GIT_COM_ID} )

            # Create a string with the version info
            set( vstring "//version_string.hh - written by cmake. changes will be lost!\n"
             "#define GIT_VERSION \"${GIT_COMMIT_ID}\"\n")

            # Write out a file containing our string
            file(WRITE gitversion.h.txt ${vstring} )

            # copy the file to the final header only if the version changes
            # reduces needless rebuilds
            execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different
                gitversion.h.txt ${CMAKE_CURRENT_BINARY_DIR}/gitversion.h)
            execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different
                gitversion.h.txt ${PROJECT_SOURCE_DIR}/gitversion.h)

            return()
        endif()
endif()

if(EXISTS ${PROJECT_SOURCE_DIR}/gitversion.h)
    message("Using static gitversion.h")
    file(COPY ${PROJECT_SOURCE_DIR}/gitversion.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    return()
endif()

message( WARNING "Failed to read git version!")

# Create a string with the version info
set( vstring "//version_string.hh - written by cmake. changes will be lost!\n"
    "#define GIT_VERSION \"unknown (git error)\"\n")

# Write out a file containing our error string
file(WRITE gitversion.h.txt ${vstring} )

# copy the file to the final header only if the version changes
# reduces needless rebuilds
execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different
    gitversion.h.txt ${CMAKE_CURRENT_BINARY_DIR}/gitversion.h)

