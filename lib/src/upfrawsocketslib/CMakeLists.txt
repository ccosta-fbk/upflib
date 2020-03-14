set(TARGETNAME UPFRawSocketsLib)
set(DIRNAME upfrawsocketslib)

add_library(${TARGETNAME} rawsockets.cpp)
target_include_directories (${TARGETNAME} PUBLIC ${UPFLIB_INCLUDE_DIR})

set_target_properties(${TARGETNAME} PROPERTIES SOVERSION 1)

target_link_libraries(${TARGETNAME} UPFNetworkLib)

file(GLOB HEADERS
  LIST_DIRECTORIES false
  ${UPFLIB_INCLUDE_DIR}/${DIRNAME}/*.hh)

set_target_properties(${TARGETNAME} PROPERTIES PUBLIC_HEADER "${HEADERS}")

install(TARGETS ${TARGETNAME}
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/${DIRNAME})
