/// @file   plugins/security/noise/tests/test_noise_ik.cpp
/// @brief  Noise IK round-trip + transport / forward-secrecy
///         coverage. Mirrors `test_noise.cpp`'s NoiseHandshakeXX
///         shape for the alternate two-message pattern where the
///         initiator already knows the responder's static pk.
///
/// IK message order:
///   ->  e, es, s, ss            (initiator -> responder)
///   <-  e, ee, se               (responder -> initiator)
///
/// Two messages vs XX's three; same Curve25519 / ChaChaPoly /
/// BLAKE2b primitives. Same `HandshakeState` class, different
/// `Pattern::IK` tag + a pre-known responder static pk on the
/// initiator's constructor.

#include <gtest/gtest.h>

#include "handshake.hpp"
#include "transport.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace gn::noise;

namespace {

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

void run_ik_handshake(HandshakeState& initiator,
                       HandshakeState& responder) {
    // -> e, es, s, ss
    auto m1 = initiator.write_message(std::span<const std::uint8_t>{});
    ASSERT_TRUE(m1.has_value());
    auto p1 = responder.read_message(*m1);
    ASSERT_TRUE(p1.has_value());
    EXPECT_TRUE(p1->empty());

    // <- e, ee, se
    auto m2 = responder.write_message(std::span<const std::uint8_t>{});
    ASSERT_TRUE(m2.has_value());
    auto p2 = initiator.read_message(*m2);
    ASSERT_TRUE(p2.has_value());
    EXPECT_TRUE(p2->empty());

    EXPECT_TRUE(initiator.is_complete());
    EXPECT_TRUE(responder.is_complete());
}

}  // namespace

TEST(NoiseHandshakeIK, FullRoundTripReachesMatchingHash) {
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();

    HandshakeState initiator(Pattern::IK, true,  init_static, &resp_static.pk);
    HandshakeState responder(Pattern::IK, false, resp_static);

    run_ik_handshake(initiator, responder);

    Digest h_i = initiator.handshake_hash();
    Digest h_r = responder.handshake_hash();
    EXPECT_EQ(std::vector<std::uint8_t>(h_i.begin(), h_i.end()),
              std::vector<std::uint8_t>(h_r.begin(), h_r.end()));
}

TEST(NoiseHandshakeIK, ResponderLearnsInitiatorStaticDuringHandshake) {
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::IK, true,  init_static, &resp_static.pk);
    HandshakeState responder(Pattern::IK, false, resp_static);
    run_ik_handshake(initiator, responder);

    /// Initiator already knew responder's static pk going in — that
    /// is the IK premise. Responder learns initiator's static during
    /// msg1 (the `s` token).
    EXPECT_EQ(initiator.peer_static_public_key(), resp_static.pk);
    EXPECT_EQ(responder.peer_static_public_key(), init_static.pk);
}

TEST(NoiseHandshakeIK, TransportCiphersInteroperate) {
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::IK, true,  init_static, &resp_static.pk);
    HandshakeState responder(Pattern::IK, false, resp_static);
    run_ik_handshake(initiator, responder);

    auto i_pair = initiator.split();
    auto r_pair = responder.split();

    TransportState init_t(std::move(i_pair.send), std::move(i_pair.recv));
    TransportState resp_t(std::move(r_pair.send), std::move(r_pair.recv));

    auto enc1 = init_t.encrypt(bytes_of("ping-ik"));
    auto dec1 = resp_t.decrypt(enc1);
    ASSERT_TRUE(dec1.has_value());
    EXPECT_EQ(*dec1, bytes_of("ping-ik"));

    auto enc2 = resp_t.encrypt(bytes_of("pong-ik"));
    auto dec2 = init_t.decrypt(enc2);
    ASSERT_TRUE(dec2.has_value());
    EXPECT_EQ(*dec2, bytes_of("pong-ik"));
}

TEST(NoiseHandshakeIK, TwoMessageVsXxThreeMessage) {
    /// Sanity-check the message-count delta the IK contract advertises:
    /// IK completes in 2 messages where XX needs 3. The bench /
    /// docs / RFC coverage matrix all cite this as the reason an
    /// operator might pick IK over XX when the peer pk is known a
    /// priori.
    EXPECT_EQ(pattern_total_steps(Pattern::IK), 2);
    EXPECT_EQ(pattern_total_steps(Pattern::XX), 3);
}

TEST(NoiseHandshakeIK, SplitZeroisesStaticSecret) {
    /// Forward-secrecy clause: same as `test_noise.cpp`'s
    /// `SplitZeroisesStaticSecretXX` — Split clears the long-term
    /// static private key inside the handshake state regardless of
    /// pattern.
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::IK, true,  init_static, &resp_static.pk);
    HandshakeState responder(Pattern::IK, false, resp_static);
    run_ik_handshake(initiator, responder);

    EXPECT_FALSE(initiator.static_secret_zeroised_for_test());
    EXPECT_FALSE(responder.static_secret_zeroised_for_test());

    [[maybe_unused]] auto i_pair = initiator.split();
    [[maybe_unused]] auto r_pair = responder.split();

    EXPECT_TRUE(initiator.static_secret_zeroised_for_test());
    EXPECT_TRUE(responder.static_secret_zeroised_for_test());
}

TEST(NoiseHandshakeIK, PayloadCarriedThroughEveryMessage) {
    /// Each handshake message may carry a plaintext-or-AEAD-
    /// encrypted payload depending on the pattern's per-step key
    /// state. Round-trip a non-empty payload through both messages
    /// to lock down that path.
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::IK, true,  init_static, &resp_static.pk);
    HandshakeState responder(Pattern::IK, false, resp_static);

    const auto pay1 = bytes_of("hello-ik-1");
    auto m1 = initiator.write_message(pay1);
    ASSERT_TRUE(m1.has_value());
    auto p1 = responder.read_message(*m1);
    ASSERT_TRUE(p1.has_value());
    EXPECT_EQ(*p1, pay1);

    const auto pay2 = bytes_of("hello-ik-2");
    auto m2 = responder.write_message(pay2);
    ASSERT_TRUE(m2.has_value());
    auto p2 = initiator.read_message(*m2);
    ASSERT_TRUE(p2.has_value());
    EXPECT_EQ(*p2, pay2);

    EXPECT_TRUE(initiator.is_complete());
    EXPECT_TRUE(responder.is_complete());
}
