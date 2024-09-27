// xorint.hpp
// Developer: suspex0
// Inspired by: https://github.com/JustasMasiulis/xorstr

#ifndef BLANK_XORINT_HPP
#define BLANK_XORINT_HPP

#include <cstdint>
#include <random>
#include <immintrin.h> // For SIMD instructions

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

        // Generates a random salt
        XORINT_FORCEINLINE std::uint64_t generate_salt() noexcept
        {
            std::random_device rd;
            std::mt19937_64 eng(rd());
            std::uniform_int_distribution<std::uint64_t> distr;
            return distr(eng);
        }

    } // namespace detail

    // xor_integer template class to handle integer encryption
    template<class T>
    class xor_integer {
        alignas(32) std::uint64_t _encrypted[4]; // Stores the encrypted integer in an aligned buffer
        std::uint64_t _salt; // Salt for the encryption

        // Generates a compile-time key
        constexpr static std::uint64_t key = detail::key8<sizeof(T)>();

    public:
        using value_type = T;

        // Constructor that XORs the integer with the key and salt at runtime
        XORINT_FORCEINLINE xor_integer(T value) noexcept
        {
            // Generate a random salt
            _salt = detail::generate_salt();

            // Encrypt the value with the key and salt
            _encrypted[0] = detail::load_from_reg((static_cast<std::uint64_t>(value) ^ key) ^ _salt);
            _encrypted[1] = _salt; // Store salt in the encrypted array for decryption
        }

        // Decrypts the integer at runtime using SIMD intrinsics
        XORINT_FORCEINLINE T crypt_get() noexcept
        {
            __m256i encrypted = _mm256_load_si256(reinterpret_cast<const __m256i*>(_encrypted));
            __m256i salt = _mm256_set1_epi64x(_encrypted[1]); // Load salt from the second part
            __m256i key_value = _mm256_set1_epi64x(key);  // Set key in all parts of the register

            // Perform XOR decryption using SIMD
            __m256i decrypted = _mm256_xor_si256(encrypted, key_value);
            decrypted = _mm256_xor_si256(decrypted, salt); // XOR with salt

            // Store the decrypted value
            _mm256_store_si256(reinterpret_cast<__m256i*>(_encrypted), decrypted);

            // Return the first decrypted value as the result
            return static_cast<T>(_encrypted[0]);
        }

        // Re-applies XOR to encrypt or decrypt the value using SIMD
        XORINT_FORCEINLINE void crypt() noexcept
        {
            __m256i encrypted = _mm256_load_si256(reinterpret_cast<const __m256i*>(_encrypted));
            __m256i salt = _mm256_set1_epi64x(_encrypted[1]); // Load salt from the second part
            __m256i key_value = _mm256_set1_epi64x(key);  // Set key in all parts of the register

            // Perform XOR encryption/decryption using SIMD
            __m256i encrypted_again = _mm256_xor_si256(encrypted, key_value);
            encrypted_again = _mm256_xor_si256(encrypted_again, salt); // XOR with salt

            _mm256_store_si256(reinterpret_cast<__m256i*>(_encrypted), encrypted_again);
        }
    };

} // namespace blank

#endif // BLANK_XORINT_HPP
