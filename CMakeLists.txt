cmake_minimum_required(VERSION 3.16)
project(password_audit LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_executable(password_audit src/main.cpp)

find_package(OpenSSL REQUIRED)
target_link_libraries(password_audit OpenSSL::Crypto)
