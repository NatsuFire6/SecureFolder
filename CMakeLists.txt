cmake_minimum_required(VERSION 4.1)
project(SecureFolder)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(SecureFolder WIN32 main.cpp)
target_link_libraries(SecureFolder PRIVATE comdlg32 shell32 advapi32 bcrypt winhttp)
