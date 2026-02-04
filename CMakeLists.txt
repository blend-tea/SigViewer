cmake_minimum_required(VERSION 3.16)

project(SigViewer VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

# Qt Advanced Docking System
add_subdirectory(Qt-Advanced-Docking-System)

# zlib: use system if found, otherwise fetch and build
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
    set(ZLIB_TARGET ZLIB::ZLIB)
else()
    include(FetchContent)
    FetchContent_Declare(
        zlib
        GIT_REPOSITORY https://github.com/madler/zlib.git
        GIT_TAG        v1.3.1
    )
    set(BUILD_SHARED_LIBS OFF)
    set(SKIP_INSTALL_ALL ON)
    FetchContent_MakeAvailable(zlib)
    set(ZLIB_TARGET zlibstatic)  # fetched zlib creates this target
    set(ZLIB_FOUND TRUE)
endif()

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        sigparser/flirtparser.cpp
        sigparser/flirtparser.h
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(SigViewer
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET SigViewer APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(SigViewer SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(SigViewer
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_include_directories(SigViewer PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/Qt-Advanced-Docking-System/src")
target_link_libraries(SigViewer PRIVATE Qt${QT_VERSION_MAJOR}::Widgets ads::qtadvanceddocking-qt${QT_VERSION_MAJOR})
if(ZLIB_FOUND)
    target_link_libraries(SigViewer PRIVATE ${ZLIB_TARGET})
    target_compile_definitions(SigViewer PRIVATE HAVE_ZLIB=1)
else()
    target_compile_definitions(SigViewer PRIVATE HAVE_ZLIB=0)
endif()

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.SigViewer)
endif()
set_target_properties(SigViewer PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS SigViewer
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(SigViewer)
endif()
