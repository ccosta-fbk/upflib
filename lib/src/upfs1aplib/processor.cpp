#include <upfs1aplib/processor.hh>

namespace UPF {
namespace S1APLib {

bool S1APProcessor::chainOnProcessSCTP_DataChunk(
    NetworkLib::EthPacketProcessor::Context &ctx) {

    if (!ctx.sctpDataChunkDecoder) {
        return true;
    }

    if (ctx.sctpDataChunkDecoder->isAFragment()) {
        // IMPORTANT: we don't deal with SCTP fragmentation
        return true;

    } else if (ctx.sctpDataChunkDecoder->isS1AP()) {
        S1APLib::S1APDecoder s1apDecoder(ctx.sctpDataChunkDecoder->getData());
        Context s1apContext(ctx, &s1apDecoder);
        auto f =
            NetworkLib::finally([&] { s1apContext.s1apDecoder = nullptr; });

        const bool result = processS1AP(s1apContext);

        // Update the EthPacketProcessor::Context with our (derived) Context
        ctx = s1apContext;

        return result;
    }

    return true;
}

} // namespace S1APLib
} // namespace UPF
