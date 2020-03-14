#include <upfnetworklib/sctp.hh>

// For std::string
#include <string>

// For std::ostringstream
#include <sstream>

namespace UPF {
namespace NetworkLib {

void SCTPDecoder::fillChunksVector() {
    std::size_t offset = startOfChunksOffset;
    const std::size_t size = mBufferView.size();

    while (offset < size) {
        // This is the unpadded length of the chunk
        const std::uint16_t chunkLength =
            mBufferView.getUint16At(offset + chunkLengthOffset);

        // This is the padded length of the chunk (multiple of 4), to
        // know where the next chunk starts (if any).
        const std::uint16_t chunkLengthWithPadding =
            ((chunkLength % 4) == 0) ? chunkLength
                                     : (((chunkLength / 4) + 1) * 4);

        // Check that the chunk is entirely within the buffer
        mBufferView.throwExceptionIfOutOfBounds(NETWORKLIB_CURRENT_FUNCTION,
                                                offset, chunkLengthWithPadding);

        // Add the chunk to our vector
        mChunks.push_back(
            SCTPGenericChunkDecoder(mBufferView.getSub(offset, chunkLength)));

        // Advance to next chunk
        offset += chunkLengthWithPadding;
    }
}

} // namespace NetworkLib
} // namespace UPF
