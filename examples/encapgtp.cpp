#include <upfdumperlib/dumper.hh>
#include <upfnetworklib/networklib.hh>
#include <upfrouterlib/upfrouterlib.hh>
#include <upfs1aplib/s1aplib.hh>

#include <iomanip>
#include <iostream>

using namespace UPF;

NetworkLib::PacketBufferPool packetPool;
NetworkLib::IPv4IdentificationSource identificationSource;

int main(int argc, char *argv[]) {
    std::ios_base::sync_with_stdio(false);

    if (argc < 4) {
        std::cerr << "Test GTP encapsulation\n";
        std::cerr << "Usage: " << argv[0]
                  << " <filename.pcap> <gtpv1u_out.pcap> <other.pcap>\n";
        return 1;
    }

    UPFRouterLib::Router upfRouter;

    try {
        NetworkLib::PcapIPv4Reader pcapReader(argv[1]);
        NetworkLib::PcapIPv4Writer pcapWriter(argv[2]);
        NetworkLib::PcapIPv4Writer pcapWriterOther(argv[3]);

        NetworkLib::BufferWritableView readBufferView =
            packetPool.getBufferWritableView();
        NetworkLib::BufferWritableView packetBufferView =
            packetPool.getBufferWritableView();

        UPFRouterLib::GTPv1UEncapSink sink(pcapWriter, packetBufferView,
                                           upfRouter, identificationSource);

        // Don't compute UDP checksum
        sink.enableUDPChecksum(false);

        // Simple loop which reads a packet, dumps info and send it out again

        // Install callback to extract GTPv1-U data and to re-encapsulate it.
        upfRouter.onGTPv1U_IPv4([&](const auto &context) -> bool {
            const NetworkLib::BufferView &ipv4Data =
                context.gtpv1uDecoder->getData();

            if (upfRouter.isIPv4TrafficOfKnownUE(ipv4Data)) {
                std::cout << "Got GTPv1-U traffic from known UE\n";
                sink.consumeIPv4Packet(ipv4Data);
                return false;
            } else {
                std::cout << "Got GTPv1-U traffic from UNKNOWN UE\n";
                // Continue processing
                return true;
            }
        });

        // Install callback for traffic that should be replicated
        upfRouter.onFinalProcess([&](const auto &context) -> bool {
            pcapWriterOther.consumeIPv4Packet(
                context.ipv4Decoder->getIPv4Packet());

            // Don't proceed further
            return false;
        });

        // Install a callbakck just to notify of new UEs.
        upfRouter.beforeUEMapUpsert(
            [](UPFRouterLib::Router::UEMapPair_t &pair) -> bool {
                std::cout << "We got a new UE: " << pair.first << ": "
                          << pair.second << '\n';

                // Allow upsert
                return true;
            });

        // Read the .pcap record by record
        while (pcapReader.packetAvailable()) {
            try {
                NetworkLib::BufferWritableView ipv4Data =
                    pcapReader.getIPv4Packet(readBufferView);

                if (!ipv4Data.empty()) {
                    upfRouter.consumeIPv4Packet(ipv4Data);
                }

            } catch (std::exception &e) {
                std::cerr << "*** caught exception: " << e.what() << '\n';
                std::cout << "*** caught exception: " << e.what() << '\n';
            }
        }
    } catch (std::exception &e) {
        std::cerr << "*** caught exception: " << e.what() << '\n';
        return 1;
    }

    std::cout << "+ UE MAP (size: " << upfRouter.getUEMap().size() << ")\n";

    for (auto const &i : upfRouter.getUEMap()) {
        std::cout << "     UE IP: " << i.first         // UE IP address
                  << " --> (eNB <-> EPC) " << i.second // GTP tunnel endpoints
                  << '\n';
    }

    std::cout << "Pool capacity: " << packetPool.capacity() << '\n'
              << "    Pool free: " << packetPool.free_count() << '\n';
}
