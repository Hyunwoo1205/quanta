# Include from the pinned HelFEM src/CMakeLists.txt after helfem-common.
add_executable(a04_helfem_cartesian "${CMAKE_CURRENT_LIST_DIR}/cartesian_density.cpp")
target_include_directories(a04_helfem_cartesian PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(a04_helfem_cartesian PRIVATE cxx_std_20)
target_link_libraries(a04_helfem_cartesian PRIVATE helfem-common legendre)
