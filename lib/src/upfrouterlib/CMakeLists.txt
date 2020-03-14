set(TARGETNAME UPFRouterLib)
set(DIRNAME upfrouterlib)


add_library(${TARGETNAME} processor.cpp router.cpp gtpencapsink.cpp rulematcher.cpp)
target_include_directories (${TARGETNAME} PUBLIC ${UPFLIB_INCLUDE_DIR})
target_include_directories (${TARGETNAME} PRIVATE ${UPFLIB_ASN1LIB_INCLUDE_DIR})

set_target_properties(${TARGETNAME} PROPERTIES SOVERSION 1)

target_link_libraries(${TARGETNAME} UPFS1APLib UPFNetworkLib)

file(GLOB HEADERS
  LIST_DIRECTORIES false
  ${UPFLIB_INCLUDE_DIR}/${DIRNAME}/*.hh)

set_target_properties(${TARGETNAME} PROPERTIES PUBLIC_HEADER "${HEADERS}")

install(TARGETS ${TARGETNAME}
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/${DIRNAME})

