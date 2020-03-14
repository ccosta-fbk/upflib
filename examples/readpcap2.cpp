#include <upfdumperlib/dumper.hh>
#include <upfnetworklib/networklib.hh>
#include <upfrouterlib/upfrouterlib.hh>
#include <upfs1aplib/s1aplib.hh>

#include <iomanip>
#include <iostream>

using namespace UPF;

NetworkLib::PacketBufferPool packetPool;

UPFRouterLib::Router router;

int main(int argc, char *argv[]) {
    using namespace NetworkLib;
    std::ios_base::sync_with_stdio(false);

    if (argc < 2) {
        std::cerr << "Dump data in the given filename.pcap file. Extract "
                     "GTPv1-U IPv4 "
                     "traffic to gtpv1u_out.pcap, if specified  \n";
        std::cerr << "Usage: " << argv[0]
                  << " <filename.pcap> [<gtpv1u_out.pcap>]\n";
        return 1;
    }

    std::cout << "Pool capacity: " << packetPool.capacity() << '\n'
              << "    Pool free: " << packetPool.free_count() << '\n';

    try {
        PcapIPv4Reader reader(argv[1]);
        std::unique_ptr<PcapIPv4Writer> writer(nullptr);

        if (argc == 3) {
            writer = std::make_unique<PcapIPv4Writer>(argv[2]);
        }

        // Simple loop which reads a packet, dumps info and send it out again
        std::size_t recordCounter = 1;
        std::size_t gtpv1uCounter = 1;

        UPFRouterLib::Processor upfRouterProcessor;

        // Setup callbacks
        upfRouterProcessor.onInitialContextSetupRequest(
            [](const auto &rs) -> bool {
                // Just dump out data
                std::cout << "We got " << rs.requests.size() << " entries \n";
                for (const auto &i : rs.requests) {
                    std::cout << i << '\n';
                }

                return true;
            });

        upfRouterProcessor.onInitialContextSetupResponse([](const auto &rs) {
            // Just dump out data
            std::cout << "We got " << rs.responses.size() << " resp entries \n";
            for (const auto &i : rs.responses) {
                std::cout << i << '\n';
            }

            return true;
        });

        if (writer) {
            // Install callback to extract GTPv1-U data
            upfRouterProcessor.onGTPv1U_IPv4([&writer, &gtpv1uCounter](
                                                 const auto &context) -> bool {
                // assert(context.gtpv1uDecoder);
                std::cout << "Copy GTPv1-U packet: " << gtpv1uCounter++ << '\n';
                writer->consumeIPv4Packet(context.gtpv1uDecoder->getData());
                return false;
            });
        }

        router.beforeUEMapUpsert(
            [](UPFRouterLib::Router::UEMapPair_t &pair) -> bool {
                std::cout << "We got a new UE: " << pair.first << ": "
                          << pair.second << '\n';

                // if (pair.first == NetworkLib::IPv4Address(192, 178, 2, 2)) {
                //     std::cout << "I don't like it! Let's change to something
                //     else\n";
                //
                //     pair.first = NetworkLib::IPv4Address(127, 0, 0, 2);
                //     return true;
                // }
                return true;
            });

        while (reader.packetAvailable()) {
            std::cout << "\n\n"
                      << "---------------------------------\n"
                      << "+ Pcap record header: " << recordCounter << '\n'
                      << "---------------------------------\n";

            try {
                BufferWritableView buffer = packetPool.getBufferWritableView();
                BufferWritableView ipv4Buffer = reader.getIPv4Packet(buffer);

                if (!ipv4Buffer.empty()) {
                    DumperLib::IPv4Dumper dumper(ipv4Buffer);
                    std::cout << dumper << '\n' << ipv4Buffer << '\n';

                    upfRouterProcessor.consumeIPv4Packet(ipv4Buffer);
                    router.consumeIPv4Packet(ipv4Buffer);
                } else {
                    std::cout << "Empty!\n";
                }

            } catch (std::exception &e) {
                std::cerr << "*** caught exception: " << e.what() << '\n';
                std::cout << "*** caught exception: " << e.what() << '\n';
            }

            recordCounter++;
        }

    } catch (std::exception &e) {

        std::cerr << "*** caught exception: " << e.what() << '\n';
        return 1;
    }

    std::cout << "+ UE MAP (size: " << router.getUEMap().size() << ")\n";

    for (auto const &i : router.getUEMap()) {
        std::cout << "     UE IP: " << i.first         // UE IP address
                  << " --> (eNB <-> EPC) " << i.second // GTP tunnel endpoints
                  << '\n';
    }

    std::cout << "Pool capacity: " << packetPool.capacity() << '\n'
              << "    Pool free: " << packetPool.free_count() << '\n';
}
