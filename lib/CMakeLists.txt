message(STATUS "distorm3?")
add_custom_target(
   distorm3
   COMMAND make
   WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/distorm3/make/linux/
)
