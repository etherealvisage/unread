add_definitions(-Wextra -Wall -std=c99 -g)
add_definitions(-D_GNU_SOURCE -Wno-unused-parameter)

aux_source_directory(. dot_sources)

include_directories(${CMAKE_CURRENT_LIST_DIR})
link_directories(${CMAKE_CURRENT_LIST_DIR})

add_executable(unread ${dot_sources})
target_link_libraries(unread distorm3)
add_dependencies(unread distorm3)
