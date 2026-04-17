#pragma once

#include <cassert>
#include <type_traits>

// narrow<To>(x): checked narrowing cast.
//
// Returns static_cast<To>(x) after asserting that the round-trip is
// lossless (the cast can be reversed to produce the original value) and
// that the sign (or lack thereof) of the value is preserved.
//
// This is NOT a substitute for validating untrusted input.  Use it only
// for known-safe narrowing casts where the compiler's -Wconversion
// reasonably flags a narrowing that the programmer has reasoned about.
// A failed assertion here means a real bug in the surrounding logic,
// not a runtime error that user input can trigger.
template <typename To, typename From>
constexpr To narrow(From x) noexcept
{
    static_assert(std::is_arithmetic_v<To>);
    static_assert(std::is_arithmetic_v<From>);
    const To y = static_cast<To>(x);
    assert(static_cast<From>(y) == x);
    // Guard each sign-mismatch comparison behind the only branch where
    // it makes sense -- otherwise -Wtype-limits would complain about
    // comparing unsigned values to zero.
    if constexpr (std::is_signed_v<To> && !std::is_signed_v<From>) {
        // unsigned -> signed: y mustn't have flipped to negative.
        assert(y >= To{});
    } else if constexpr (!std::is_signed_v<To> && std::is_signed_v<From>) {
        // signed -> unsigned: x must have been non-negative to start with.
        assert(x >= From{});
    }
    return y;
}

