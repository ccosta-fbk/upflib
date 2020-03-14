set(TARGETNAME UPFNetworkLib)
set(DIRNAME upfnetworklib)


add_library(${TARGETNAME}
  utils.cpp
  buffers.cpp
  interfaces.cpp
  ethernet.cpp
  ipv4.cpp
  ipv4encap.cpp
  pcap.cpp
  tcp.cpp
  sctp.cpp
  udp.cpp
  gtp_u.cpp
  gtp_u_encap.cpp
  processor.cpp)

target_include_directories (${TARGETNAME} PUBLIC ${UPFLIB_INCLUDE_DIR})

set_target_properties(${TARGETNAME} PROPERTIES SOVERSION 1)

file(GLOB HEADERS
  LIST_DIRECTORIES false
  ${UPFLIB_INCLUDE_DIR}/${DIRNAME}/*.hh)

set_target_properties(${TARGETNAME} PROPERTIES PUBLIC_HEADER "${HEADERS}")

install(TARGETS ${TARGETNAME}
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/${DIRNAME})
