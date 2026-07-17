cmake_minimum_required(VERSION 3.20)
project(cmproj C)
# Known-closure fixture for the io-mon real-build completeness oracle.
# Every source input below is enumerable by construction; see oracle.nim.
add_executable(cmproj src/main.c src/foo.c src/bar.c)
