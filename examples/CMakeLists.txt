add_executable(sample1 sample1.cpp)
target_link_libraries (sample1 LINK_PUBLIC ${UPFLIB_LIBS})

add_executable(repeater repeater.cpp)
target_link_libraries (repeater LINK_PUBLIC ${UPFLIB_LIBS})

add_executable(readpcap2 readpcap2.cpp)
target_link_libraries (readpcap2 LINK_PUBLIC ${UPFLIB_LIBS})

add_executable(copygtp copygtp.cpp)
target_link_libraries (copygtp LINK_PUBLIC ${UPFLIB_LIBS})

add_executable(encapgtp encapgtp.cpp)
target_link_libraries (encapgtp LINK_PUBLIC ${UPFLIB_LIBS})

add_executable(ipv4address ipv4address.cpp)
target_link_libraries (ipv4address LINK_PUBLIC ${UPFLIB_LIBS})

add_executable(macaddress macaddress.cpp)
target_link_libraries (macaddress LINK_PUBLIC ${UPFLIB_LIBS})

add_executable(matchingrule matchingrule.cpp)
target_link_libraries (matchingrule LINK_PUBLIC ${UPFLIB_LIBS})

add_executable(printsize printsize.cpp)
target_link_libraries (printsize LINK_PUBLIC ${UPFLIB_LIBS})
# Do not build printsize by default (takes a lot of time)
set_target_properties(printsize PROPERTIES EXCLUDE_FROM_ALL 1)
