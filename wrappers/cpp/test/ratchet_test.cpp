// C++ SDK smoke test for the ratchet library. A full X3DH round-trip needs
// two-party key material; this exercises construction, setup, and a basic query,
// proving the ratchet C++ API links and runs. setup_defaults() wires up ratchet's
// foundation-backed dependencies (a foundation CtrDrbg rng), so the cross-project
// link is exercised at runtime; set_rng is an alternative to setup_defaults (the C
// API asserts the dependency is unset), so the two are not combined here.
#include <virgil/crypto/ratchet/ratchet_session.hpp>

#include "check.hpp"

namespace r = virgil::crypto::ratchet;

static void test_ratchet_session_setup() {
    r::RatchetSession session;
    CHECK(session.setup_defaults().has_value());

    // A freshly constructed, un-initiated session is not the initiator.
    CHECK(!session.is_initiator());
}

int main() {
    test_ratchet_session_setup();
    TEST_MAIN_RETURN();
}
