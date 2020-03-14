#include <iomanip>
#include <iostream>
#include <upfdumperlib/dumper.hh>
#include <upfnetworklib/networklib.hh>
#include <upfrouterlib/upfrouterlib.hh>
#include <upfs1aplib/s1aplib.hh>

#include <ostream>

using namespace UPF;

void dumpSizeof(std::ostream &ostr) {

#define W 50
#define DUMP_SIZE_OF(T) '|' << std::setw(W) << "sizeof(): " << sizeof(T) << '\n'

#define DUMP_TRAITS_OF(T)                                                      \
    '|' << std::setw(W) << "           std::is_copy_constructible: "           \
        << std::is_copy_constructible<T>::value << '\n'                        \
        << '|' << std::setw(W) << " std::is_trivially_copy_constructible: "    \
        << std::is_trivially_copy_constructible<T>::value << '\n'              \
        << '|' << std::setw(W) << "   std::is_nothrow_copy_constructible: "    \
        << std::is_nothrow_copy_constructible<T>::value << '\n'                \
        << '|' << std::setw(W) << "           std::is_move_constructible: "    \
        << std::is_move_constructible<T>::value << '\n'                        \
        << '|' << std::setw(W) << " std::is_trivially_move_constructible: "    \
        << std::is_trivially_move_constructible<T>::value << '\n'              \
        << '|' << std::setw(W) << "   std::is_nothrow_move_constructible: "    \
        << std::is_nothrow_move_constructible<T>::value << '\n'

#define DUMP_INFO_OF(T)                                                        \
    std::setw(W)                                                               \
        << "------------------------------------------------------------"      \
        << '\n'                                                                \
        << "| " #T << '\n'                                                     \
        << "|\n"                                                               \
        << DUMP_SIZE_OF(T) << "|\n| Traits\n"                                  \
        << DUMP_TRAITS_OF(T) << '\n'

    ostr << DUMP_INFO_OF(NetworkLib::IPv4Address)
         << DUMP_INFO_OF(NetworkLib::MACAddress)
         << DUMP_INFO_OF(NetworkLib::PacketBuffer)
         << DUMP_INFO_OF(NetworkLib::PacketBufferArrayBased<1000>)
         << DUMP_INFO_OF(NetworkLib::PacketBufferPool)
         << DUMP_INFO_OF(NetworkLib::BufferView)
         << DUMP_INFO_OF(NetworkLib::BufferWritableView)
         << DUMP_INFO_OF(NetworkLib::EthFrameDecoder)
         << DUMP_INFO_OF(NetworkLib::IPv4FragmentKey)
         << DUMP_INFO_OF(NetworkLib::RangeDescriptor)
         << DUMP_INFO_OF(NetworkLib::IPv4Decoder)
         << DUMP_INFO_OF(NetworkLib::IPv4ReassemblyBuffer)
         << DUMP_INFO_OF(NetworkLib::TCPDecoder)
         << DUMP_INFO_OF(NetworkLib::UDPDecoder)
         << DUMP_INFO_OF(NetworkLib::SCTPGenericChunkDecoder)
         << DUMP_INFO_OF(NetworkLib::SCTPDataChunkDecoder)
         << DUMP_INFO_OF(NetworkLib::SCTPDecoder)
         << DUMP_INFO_OF(NetworkLib::GTPv1UDecoder)
         << DUMP_INFO_OF(NetworkLib::PcapHeader)
         << DUMP_INFO_OF(NetworkLib::PcapRecord)
         << DUMP_INFO_OF(NetworkLib::PcapReader)
         << DUMP_INFO_OF(NetworkLib::PcapWriter)
         << DUMP_INFO_OF(NetworkLib::PcapIPv4Reader)
         << DUMP_INFO_OF(NetworkLib::PcapIPv4Writer)
         << DUMP_INFO_OF(NetworkLib::EthPacketProcessor)
         << DUMP_INFO_OF(NetworkLib::EthPacketProcessor::Context)
         << DUMP_INFO_OF(S1APLib::S1APDecoder)
         << DUMP_INFO_OF(S1APLib::NASDecoder)
         << DUMP_INFO_OF(S1APLib::PDNAddressDecoder)
         << DUMP_INFO_OF(S1APLib::NASPlainAttachAcceptDecoder)
         << DUMP_INFO_OF(S1APLib::NASActivateDefaultEPSBearerContextDecoder)
         << DUMP_INFO_OF(S1APLib::S1APProcessor)
         << DUMP_INFO_OF(S1APLib::S1APProcessor::Context)
         << DUMP_INFO_OF(UPFRouterLib::Processor)
         << DUMP_INFO_OF(UPFRouterLib::Router)
         << DUMP_INFO_OF(
                UPFRouterLib::Processor::InitialContextSetupRequestData)
         << DUMP_INFO_OF(
                UPFRouterLib::Processor::InitialContextSetupResponseData)
         << DUMP_INFO_OF(unsigned long) << DUMP_INFO_OF(unsigned int)
         << DUMP_INFO_OF(unsigned short);

#undef DUMP_INFO_OF
#undef DUMP_TRAITS_OF
#undef DUMP_SIZE_OF
#undef W
}

int main(int, char *[]) {
    std::cout << "Info on common types" << '\n';
    dumpSizeof(std::cout);
    return 0;
}
