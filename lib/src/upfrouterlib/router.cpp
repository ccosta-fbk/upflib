#include <upfrouterlib/router.hh>

// For std::make_pair
#include <utility>

namespace UPF {
namespace UPFRouterLib {

Router::Router() {
    // Setup callbacks
    mProcessor.onInitialContextSetupRequest(
        [this](const Requests &reqs) -> bool {
            return this->handleRequests(reqs);
        });

    mProcessor.onInitialContextSetupResponse(
        [this](const Responses &resps) -> bool {
            return this->handleResponses(resps);
        });
}

bool Router::handleRequests(const Requests &reqs) {
    // Note: it should always be just one request
    if (mOnS1APRelevantTrafficCbk) {
        mOnS1APRelevantTrafficCbk();
    }

    for (const Request &i : reqs.requests) {

        SetupKey key(i);

        // Add an entry to the setup map, or update it.
        SetupData &setupData = mSetupMap[key];

        // Requests goes from EPC to eNodeBs
        setupData.tunnelInfo.epcEndPoint.ipAddress = i.transportLayerAddress;
        setupData.tunnelInfo.epcEndPoint.teid = i.gtp_teid;

        // Keep this for later...
        setupData.ueAddress = i.UEIPv4Address;
    }

    // Continue processing, but don't call postProcessIPv4().
    reqs.context.postProcessIPv4 = false;
    return true;
}

bool Router::handleResponses(const Responses &resps) {

    // Note: it should always be just one response
    if (mOnS1APRelevantTrafficCbk) {
        mOnS1APRelevantTrafficCbk();
    }

    for (const Response &i : resps.responses) {
        SetupKey key(i);

        auto t = mSetupMap.find(key);

        if (t == mSetupMap.end()) {
            // Key not found... we have a response without a request.
        } else {
            // Alias (from iterator)
            SetupData &setupData(t->second);

            // Fill in the missing info...

            // Reqsponses go from from eNodeBs to EPC
            setupData.tunnelInfo.eNBEndPoint.ipAddress =
                i.transportLayerAddress;
            setupData.tunnelInfo.eNBEndPoint.teid = i.gtp_teid;

            // Prepare the new entry
            auto newMapEntry =
                std::make_pair(setupData.ueAddress, setupData.tunnelInfo);

            // Remove entry from setup map
            mSetupMap.erase(t);

            bool doIt = true;
            if (mBeforeUEMapUpsertCbk) {
                doIt = mBeforeUEMapUpsertCbk(newMapEntry);
            }

            if (doIt) {
                // Upsert the value in the UE map
                mUEMap[newMapEntry.first] = newMapEntry.second;
            }
        }
    }

    // Continue processing, but don't call postProcessIPv4().
    resps.context.postProcessIPv4 = false;
    return true;
}

} // namespace UPFRouterLib
} // namespace UPF
