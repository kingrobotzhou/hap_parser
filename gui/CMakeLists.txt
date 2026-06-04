cmake_minimum_required(VERSION 3.20)
project(hap_analyzer_gui VERSION 1.0 LANGUAGES C CXX OBJCXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── OpenSSL ─────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")

# ── GLFW ────────────────────────────────────────────────
find_package(glfw3 QUIET)
if(NOT glfw3_FOUND)
    message(STATUS "GLFW not found, downloading via FetchContent...")
    include(FetchContent)
    FetchContent_Declare(glfw
        GIT_REPOSITORY  https://github.com/glfw/glfw.git
        GIT_TAG         3.4
        GIT_SHALLOW     TRUE
    )
    set(GLFW_BUILD_DOCS     OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(GLFW_INSTALL        OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(glfw)
endif()

# ── Dear ImGui (local) ──────────────────────────────────
set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/imgui)
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3_loader.h
)

# ── Sources ─────────────────────────────────────────────
set(HAP_PARSER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../hap_parser)
set(HAP_SOURCES
    ${HAP_PARSER_DIR}/hap_parser.cpp
    ${HAP_PARSER_DIR}/runtime_verify.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/HapAnalyzer.cpp
)
set(GUI_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/AppState.cpp
)
if(APPLE)
    list(APPEND GUI_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/macos_bridge.mm)
endif()

# ── Fonts (bundle resources) ────────────────────────────
if(APPLE)
    set(FONT_FILES ${CMAKE_CURRENT_SOURCE_DIR}/fonts/Hiragino.ttc)
    set_source_files_properties(${FONT_FILES} PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources"
    )
endif()

# ── Executable ──────────────────────────────────────────
add_executable(hap_analyzer_gui
    ${GUI_SOURCES} ${IMGUI_SOURCES} ${HAP_SOURCES}
)
if(APPLE)
    target_sources(hap_analyzer_gui PRIVATE ${FONT_FILES})
endif()

set_target_properties(hap_analyzer_gui PROPERTIES
    MACOSX_BUNDLE TRUE
    MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in
    MACOSX_BUNDLE_BUNDLE_NAME "HAP Analyzer"
    MACOSX_BUNDLE_BUNDLE_VERSION "1.0"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.hap.analyzer"
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
    XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO"
    XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
)

target_include_directories(hap_analyzer_gui PRIVATE
    ${HAP_PARSER_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(hap_analyzer_gui PRIVATE
    glfw
    OpenSSL::SSL
    OpenSSL::Crypto
)
if(APPLE)
    target_link_libraries(hap_analyzer_gui PRIVATE
        "-framework OpenGL"
        "-framework Cocoa"
        "-framework IOKit"
        "-framework CoreVideo"
    )
endif()
if(WIN32)
    target_link_libraries(hap_analyzer_gui PRIVATE opengl32)
endif()
if(UNIX AND NOT APPLE)
    target_link_libraries(hap_analyzer_gui PRIVATE
        "-lGL" "-ldl" "-lpthread"
    )
endif()

target_compile_definitions(hap_analyzer_gui PRIVATE
    $<$<BOOL:${APPLE}>:GL_SILENCE_DEPRECATION>
)
