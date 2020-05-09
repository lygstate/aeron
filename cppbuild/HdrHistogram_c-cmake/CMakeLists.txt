find_package(Threads REQUIRED)

include(CheckLibraryExists)
check_library_exists(m ceil "" HAVE_LIBM)
check_library_exists(rt clock_gettime "" HAVE_LIBRT)

set(HDR_HISTOGRAM_SOURCES
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_encoding.c
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_histogram.c
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_histogram_log.c
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_interval_recorder.c
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_thread.c
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_time.c
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_writer_reader_phaser.c)

set(HDR_HISTOGRAM_PRIVATE_HEADERS
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_atomic.h
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_encoding.h
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_endian.h
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_tests.h)

set(HDR_HISTOGRAM_PUBLIC_HEADERS
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_histogram.h
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_histogram_log.h
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_interval_recorder.h
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_thread.h
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_time.h
    ${HDRHISTOGRAM_SOURCE_DIR}/src/hdr_writer_reader_phaser.h)

function(hdr_histogram_add_library NAME LIBRARY_TYPE DO_INSTALL)
    add_library(${NAME} ${LIBRARY_TYPE}
        ${HDR_HISTOGRAM_SOURCES}
        ${HDR_HISTOGRAM_PRIVATE_HEADERS}
        ${HDR_HISTOGRAM_PUBLIC_HEADERS})
    target_link_libraries(${NAME}
        PRIVATE
            ${ZLIB_LIBRARIES}
            Threads::Threads
            $<$<BOOL:${HAVE_LIBM}>:m>
            $<$<BOOL:${HAVE_LIBRT}>:rt>
            $<$<BOOL:${WIN32}>:ws2_32>)
    target_include_directories(${NAME}
        PUBLIC
            ${ZLIB_INCLUDE_DIRS}
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    if(DO_INSTALL)
        install(
            TARGETS ${NAME}
            EXPORT ${PROJECT_NAME}-targets
            DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()
endfunction()

option(HDR_HISTOGRAM_BUILD_SHARED "Build shared library" ON)
option(HDR_HISTOGRAM_INSTALL_SHARED "Install shared library" ON)
if(HDR_HISTOGRAM_BUILD_SHARED)
    hdr_histogram_add_library(hdr_histogram SHARED ${HDR_HISTOGRAM_INSTALL_SHARED})
    set_target_properties(hdr_histogram PROPERTIES
        VERSION ${HDR_VERSION}
        SOVERSION ${HDR_SOVERSION})
endif()

option(HDR_HISTOGRAM_BUILD_STATIC "Build static library" ON)
option(HDR_HISTOGRAM_INSTALL_STATIC "Install static library" ON)
if(HDR_HISTOGRAM_BUILD_STATIC)
    hdr_histogram_add_library(hdr_histogram_static STATIC ${HDR_HISTOGRAM_INSTALL_STATIC})
endif()

install(
    FILES ${HDR_HISTOGRAM_PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hdr)
