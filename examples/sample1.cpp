#include <upfdumperlib/dumper.hh>
#include <upfnetworklib/networklib.hh>
#include <upfrawsocketslib/rawsockets.hh>

#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>

using namespace UPF;

NetworkLib::PacketBufferPool packetPool;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Dump data received by the given network interface\n";
        std::cerr << "Usage: " << argv[0] << " <ifName>\n";
        return 1;
    }

    std::string ifName(argv[1]);

    try {
        std::cout << "Searching ifIndex of interface " << ifName << "...\n";
        auto ifIndex = RawSocketsUtil::getIfIndexByIfName(ifName);
        std::cout << "ifIndex of " << ifName << " is " << ifIndex << '\n';

        auto fd1 =
            openByIfIndex(ifIndex, RawSocketsUtil::PROMISCUOS_MODE_ENABLED);

        std::cout << "Getting MTU...\n";
        auto savedMTU = RawSocketsUtil::getMTU(fd1, ifName);

        std::cout << "MTU is " << savedMTU << '\n';

        NetworkLib::BufferWritableView bufferWritableView =
            packetPool.getBufferWritableView();

        // Simple loop which reads a packet, dumps info and send it out again
        while (true) {

            auto ethData = RawSocketsUtil::receiveData(fd1, bufferWritableView);

            std::cout << "\n\n"
                      << "---------------------------------\n"
                      << ">>> Read " << ethData.size() << " bytes\n"
                      << "---------------------------------\n";

            // Decode the frame and dump it
            DumperLib::EthDumper dumper(ethData);
            std::cout << dumper << '\n';

            // In any case, dump the buffer.
            std::cout << ethData << '\n';
        }

    } catch (std::exception &e) {

        std::cerr << "*** caught exception: " << e.what() << '\n';
        return 1;
    }
}
