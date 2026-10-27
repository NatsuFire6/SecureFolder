cmake_minimum_required(VERSION 4.1)
project(SecureFolder)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Populate(
    WindowsInfo
    GIT_REPOSITORY https://github.com/NatsuFire6/WindowsInfo.git
    GIT_TAG d2a77c56c4dea695109b76a966d5e3e0635404b1
)

add_library(WindowsInfoLib STATIC
    "${windowsinfo_SOURCE_DIR}/window_save_manager.cpp"
)
target_include_directories(WindowsInfoLib PUBLIC "${windowsinfo_SOURCE_DIR}")
target_link_libraries(WindowsInfoLib PUBLIC user32)

add_executable(SecureFolder WIN32 main.cpp)
target_link_libraries(SecureFolder PRIVATE comdlg32 shell32 advapi32 bcrypt winhttp WindowsInfoLib)
