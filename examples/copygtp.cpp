#include <upfdumperlib/dumper.hh>
#include <upfnetworklib/networklib.hh>
#include <upfs1aplib/s1aplib.hh>

#include <iomanip>
#include <iostream>

using namespace UPF;

NetworkLib::PacketBufferPool packetPool;

class GTPDecapper : public NetworkLib::EthPacketProcessor {
  public:
    GTPDecapper(NetworkLib::IPv4PacketSink &sink) : mSink(sink) {}

    virtual ~GTPDecapper() {}

    virtual bool processGTPv1U_IPv4(Context &ctx) {
        if (ctx.gtpv1uDecoder) {
            mSink.consumeIPv4Packet(ctx.gtpv1uDecoder->getData());
        }

        return false;
    }

  private:
    NetworkLib::IPv4PacketSink &mSink;
};

int main(int argc, char *argv[]) {
    using namespace NetworkLib;
    std::ios_base::sync_with_stdio(false);

    if (argc < 3) {
        std::cerr << "Read in.pcap, extract GTP-encpasulated IPv4 "
                     "data to out.pcap\n";
        std::cerr << "Usage: " << argv[0] << " <in.pcap> <out.pcap>\n";
        return 1;
    }

    std::cout << "Pool capacity: " << packetPool.capacity() << '\n'
              << "    Pool free: " << packetPool.free_count() << '\n';

    try {
        PcapEthReader reader(argv[1]);
        PcapIPv4Writer writer(argv[2]);
        GTPDecapper gtpsink(writer);

        // Simple loop which reads a packet, dumps info and send it out again
        std::size_t recordCounter = 1;

        while (reader.packetAvailable()) {
            try {
                BufferWritableView buffer = packetPool.getBufferWritableView();
                BufferWritableView ethBuffer = reader.getEthPacket(buffer);

                if (!ethBuffer.empty()) {
                    gtpsink.consumeEthPacket(ethBuffer);
                }

            } catch (std::exception &e) {
                std::cerr << "*** caught exception at record: " << recordCounter
                          << ": " << e.what() << '\n';
            }

            recordCounter++;
        }

    } catch (std::exception &e) {

        std::cerr << "*** caught exception: " << e.what() << '\n';
        return 1;
    }

    std::cout << "Pool capacity: " << packetPool.capacity() << '\n'
              << "    Pool free: " << packetPool.free_count() << '\n';
}
