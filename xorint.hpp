#ifndef BLANK_XORINT_HPP
#define BLANK_XORINT_HPP

// Developer: suspex0
// Inspired by: https://github.com/JustasMasiulis/xorstr

#include <cstdint>
#include <immintrin.h> // For SIMD and AES-NI instructions

#define xorint(value) ::blank::xor_integer<decltype(value)>(value)  // Direct integer encryption
#define xorint_(value) xorint(value).crypt_get()  // Decrypt macro

#ifdef _MSC_VER
#define XORINT_FORCEINLINE __forceinline
#else
#define XORINT_FORCEINLINE __attribute__((always_inline)) inline
#endif

namespace blank {

    namespace detail {

        // Generates a 32-bit key from a seed, based on __TIME__
        template<std::uint32_t Seed>
        XORINT_FORCEINLINE constexpr std::uint32_t key4() noexcept
        {
            std::uint32_t value = Seed;
            for (char c : __TIME__)
                value = static_cast<std::uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        // Combines two 32-bit keys into a 64-bit key
        template<std::size_t S>
        XORINT_FORCEINLINE constexpr std::uint64_t key8()
        {
            constexpr auto first_part = key4<2166136261 + S>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<std::uint64_t>(first_part) << 32) | second_part;
        }

        // Forces compiler to load the value into a register
        XORINT_FORCEINLINE std::uint64_t load_from_reg(std::uint64_t value) noexcept
        {
#if defined(__clang__) || defined(__GNUC__)
            asm("" : "=r"(value) : "0"(value) : );
            return value;
#else
            volatile std::uint64_t reg = value;
            return reg;
#endif
        }

        // AES-NI encryption using a key (AES 128-bit for simplicity)
        XORINT_FORCEINLINE __m128i aes_encrypt(__m128i data, __m128i key) noexcept
        {
            data = _mm_xor_si128(data, key);                // Initial round key addition
            data = _mm_aesenc_si128(data, key);             // AES round
            data = _mm_aesenc_si128(data, key);             // AES round
            data = _mm_aesenc_si128(data, key);             // AES round
            data = _mm_aesenc_si128(data, key);             // AES round
            data = _mm_aesenc_si128(data, key);             // AES round
            data = _mm_aesenc_si128(data, key);             // AES round
            data = _mm_aesenc_si128(data, key);             // AES round
            data = _mm_aesenclast_si128(data, key);         // Final round (no MixColumns)
            return data;
        }

        // AES-NI decryption using a key
        XORINT_FORCEINLINE __m128i aes_decrypt(__m128i data, __m128i key) noexcept
        {
            data = _mm_xor_si128(data, key);                // Initial round key addition
            data = _mm_aesdec_si128(data, key);             // AES round
            data = _mm_aesdec_si128(data, key);             // AES round
            data = _mm_aesdec_si128(data, key);             // AES round
            data = _mm_aesdec_si128(data, key);             // AES round
            data = _mm_aesdec_si128(data, key);             // AES round
            data = _mm_aesdec_si128(data, key);             // AES round
            data = _mm_aesdec_si128(data, key);             // AES round
            data = _mm_aesdeclast_si128(data, key);         // Final round (no MixColumns)
            return data;
        }

    } // namespace detail

    // xor_integer template class to handle integer encryption using AES-NI
    template<class T>
    class xor_integer {
        alignas(16) std::uint64_t _encrypted[2]; // Stores the encrypted integer in an aligned buffer

        // Generates a compile-time key
        constexpr static std::uint64_t key = detail::key8<sizeof(T)>();

    public:
        using value_type = T;

        // Constructor that encrypts the integer using AES-NI at runtime
        XORINT_FORCEINLINE xor_integer(T value) noexcept
        {
            __m128i aes_key = _mm_set1_epi64x(key);  // Set AES key
            __m128i data = _mm_set1_epi64x(static_cast<std::uint64_t>(value));
            __m128i encrypted = detail::aes_encrypt(data, aes_key);

            _mm_store_si128(reinterpret_cast<__m128i*>(_encrypted), encrypted);
        }

        // Decrypts the integer using AES-NI at runtime
        XORINT_FORCEINLINE T crypt_get() noexcept
        {
            __m128i aes_key = _mm_set1_epi64x(key);  // Set AES key
            __m128i encrypted = _mm_load_si128(reinterpret_cast<const __m128i*>(_encrypted));
            __m128i decrypted = detail::aes_decrypt(encrypted, aes_key);

            std::uint64_t result;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&result), decrypted);
            return static_cast<T>(result);
        }

        // Encrypts/decrypts the value again (reversible AES)
        XORINT_FORCEINLINE void crypt() noexcept
        {
            __m128i aes_key = _mm_set1_epi64x(key);  // Set AES key
            __m128i data = _mm_load_si128(reinterpret_cast<const __m128i*>(_encrypted));
            __m128i encrypted = detail::aes_encrypt(data, aes_key);
            _mm_store_si128(reinterpret_cast<__m128i*>(_encrypted), encrypted);
        }
    };

} // namespace blank

#endif // BLANK_XORINT_HPP
