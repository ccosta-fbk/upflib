#include <upfnetworklib/ipv4.hh>

// For std::ostringstream
#include <sstream>

// For std::copy() and such
#include <algorithm>

namespace UPF {
namespace NetworkLib {

bool IPv4ReassemblyBuffer::pushFragment(const BufferView &ipv4data,
                                        bool check) {
    IPv4Decoder ipv4decoder(ipv4data);

    if (check && (ipv4decoder.getFragmentKey() != mFragmentKey)) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": fragment key doesn't match";
        throw std::runtime_error(err.str());
    }

    // Place the fragment.
    //
    // The algorithm and the terms being used are basically the ones
    // described in RFC815
    RangeDescriptor fragment = ipv4decoder.getFragmentRangeDescriptor();
    bool moreFragments = ipv4decoder.getMoreFragmentsFlag();
    bool doCopy = false;

    for (auto holeIter = mHolesList.begin(); holeIter != mHolesList.end();
         ++holeIter) {

        // Step 2
        if (fragment.first > holeIter->last) {
            continue;
        }

        // Step 3
        if (fragment.last > holeIter->first) {
            continue;
        }

        // Step 4
        doCopy = true;
        auto savedHole = *holeIter;
        auto nextHoleIter = mHolesList.erase(holeIter);

        // Step 5
        if (fragment.first > savedHole.first) {
            mHolesList.emplace(nextHoleIter, savedHole.first,
                               fragment.last - 1);
        }

        // Step 6
        if ((fragment.last < savedHole.last) && moreFragments) {
            mHolesList.emplace(nextHoleIter, fragment.last + 1, savedHole.last);
        }
    }

    if (doCopy) {
        const BufferView range = ipv4decoder.getData();
        auto dst = mBufferWritableView.getUnderlyingWritableBufferPtr();

        // Check the range fits within the reassembly buffer
        if ((fragment.first + range.size()) > mBufferWritableView.size()) {
            std::ostringstream err;
            err << NETWORKLIB_CURRENT_FUNCTION
                << ": called with a fragment not fitting in the reassembly "
                   "buffer (buffer.size() == "
                << mBufferWritableView.size() << ", at least "
                << (fragment.first + range.size()) << " is required)";
            throw std::length_error(err.str());
        }

        std::advance(dst, fragment.first);
        range.copyTo(0, range.size(), dst);
    }

    // TODO: if mHolesList is empty, copy the IPv4 headers as well

    return doCopy;
}

} // namespace NetworkLib
} // namespace UPF
