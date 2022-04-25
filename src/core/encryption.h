#pragma once

#include <array>
#include <iostream>
#include <vector>

namespace encryption {

class RSAKey {
private:
    uint64_t m_exponent;
    uint64_t m_modulus;

public:
    RSAKey();

    RSAKey(uint64_t exponent, uint64_t modulus);

    uint64_t get_exponent() const;
    uint64_t get_modulus() const;

    friend std::ostream& operator<<(std::ostream& output_stream,
                                    const RSAKey& key);
};

class RSAInstance {
private:
    RSAKey m_public_key;
    RSAKey m_private_key;

public:
    RSAInstance(RSAKey public_key, RSAKey private_key);
    std::string encrypt(const std::string& message) const;
    std::string decrypt(const std::string& message) const;
};

class RSAEncryption {
private:
    static std::array<uint64_t, 3> generate_keys(
        const std::vector<uint64_t>& primes);
    static uint64_t define_e(uint64_t phi_n);
    static uint64_t define_d(uint64_t e, uint64_t phi_n);

public:
    static RSAInstance from(const std::vector<uint64_t>& primes);
};
}  // namespace encryption
