
#include <iostream>
#include <vector>
#include <array>

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

class RSAStaticKey
{
private:
    uint64_t exponent;
    uint64_t modulus;

public:
    RSAStaticKey();

    RSAStaticKey(uint64_t exponent, uint64_t modulus);

    uint64_t get_exponent();
    uint64_t get_modulus();
    std::string to_string();
};

class RSAEncryption
{
private:
    RSAStaticKey public_key;
    RSAStaticKey private_key;

public:
    RSAEncryption(RSAStaticKey public_key, RSAStaticKey private_key);
    std::string encrypt(std::string message);
    std::string decrypt(std::string message);
};

class RSAKey
{
private:
    static std::array<uint64_t, 3> generate_keys(std::vector<uint64_t> &primes);
    static uint64_t define_e(uint64_t phi_n);
    static uint64_t define_d(uint64_t e, uint64_t phi_n);

public:
    static RSAEncryption from(std::vector<uint64_t> &primes);
};

#endif