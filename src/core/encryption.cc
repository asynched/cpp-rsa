#include <iostream>
#include <vector>
#include <array>
#include <sstream>
#include <bits/stdc++.h>
#include "../utils/math.h"
#include "encryption.h"

namespace encryption
{

    /**
     * @brief Construct a new RSAStaticKey::RSAStaticKey object.
     *
     */
    RSAStaticKey::RSAStaticKey()
    {
        this->exponent = 0;
        this->modulus = 0;
    }

    /**
     * @brief Construct a new RSAStaticKey::RSAStaticKey object.
     *
     * @param exponent Exponent for the key.
     * @param modulus Modulus for the key.
     */
    RSAStaticKey::RSAStaticKey(uint64_t exponent, uint64_t modulus)
    {
        this->exponent = exponent;
        this->modulus = modulus;
    }

    /**
     * @brief Getter for the exponent of the object.
     *
     * @return uint64_t Exponent of the object.
     */
    uint64_t RSAStaticKey::get_exponent()
    {
        return this->exponent;
    }

    /**
     * @brief Getter for the modulus of the object.
     *
     * @return uint64_t Modulus of the object.
     */
    uint64_t RSAStaticKey::get_modulus()
    {
        return this->modulus;
    }

    /**
     * @brief Generates a string representation of the object.
     *
     * @return std::string String representation of the static key.
     */
    std::string RSAStaticKey::to_string()
    {
        return std::string("RSAStaticKey<") + std::to_string(this->exponent) + "," + std::to_string(this->modulus) + std::string(">");
    }

    /**
     * @brief Construct a new RSAEncryption::RSAEncryption object.
     *
     * @param public_key Object's public key.
     * @param private_key Object's private key.
     */
    RSAEncryption::RSAEncryption(RSAStaticKey public_key, RSAStaticKey private_key)
    {
        this->public_key = public_key;
        this->private_key = private_key;
    }

    /**
     * @brief Encrypts a message with the given object's public key.
     *
     * @param message Message to be encrypted.
     * @return std::string Encrypted message.
     */
    std::string RSAEncryption::encrypt(std::string message)
    {
        auto encrypted = std::string();

        for (const auto &c : message)
        {
            auto encrypted_char = math::power((uint64_t)c, this->public_key.get_exponent(), this->public_key.get_modulus());
            encrypted += std::to_string(encrypted_char) + " ";
        }
        return encrypted;
    }

    /**
     * @brief Decrypts a message with the given object's private key.
     *
     * @param message Message to be decrypted.
     * @return std::string Decrypted message.
     */
    std::string RSAEncryption::decrypt(std::string message)
    {
        auto stream = std::stringstream(message);

        auto decrypted = std::string();

        while (stream.good())
        {
            auto mod = 0;
            stream >> mod;

            if (stream.good())
            {
                auto decrypted_char = math::power(mod, this->private_key.get_exponent(), this->private_key.get_modulus());
                decrypted += (char)decrypted_char;
            }
        }

        return decrypted;
    }

    /**
     * @brief Generates a new RSA key pair.
     *
     * @param primes Primes list to generate the key pair from.
     * @return std::array<uint64_t, 3> Array containing the public and private keys, ordered in e, d and n.
     */
    std::array<uint64_t, 3> RSAKey::generate_keys(std::vector<uint64_t> &primes)
    {
        auto p = primes[std::rand() % primes.size()];
        auto q = primes[std::rand() % primes.size()];

        auto n = p * q;
        auto phi_n = (p - 1) * (q - 1);

        auto e = RSAKey::define_e(phi_n);
        auto d = RSAKey::define_d(e, phi_n);

        std::array<uint64_t, 3> keys = {e, d, n};

        return keys;
    }

    /**
     * @brief Defines the encrypt value of the public key.
     *
     * @param phi_n Phi of N.
     * @return uint64_t Encrypt value of the public key.
     */
    uint64_t RSAKey::define_e(uint64_t phi_n)
    {
        while (1)
        {
            auto e = std::rand() % phi_n;

            if (std::__gcd(e, phi_n) == 1)
            {
                return e;
            }
        }
    }

    /**
     * @brief Defines the decrypt value of the private key.
     *
     * @param e Encrypt value of the public key.
     * @param phi_n Phi of N.
     * @return uint64_t Decrypt value of the private key.
     */
    uint64_t RSAKey::define_d(uint64_t e, uint64_t phi_n)
    {
        auto phi_aux = phi_n;

        int64_t x = 0, old_y = 0;
        int64_t y = 1, old_x = 1;

        while (phi_n != 0)
        {
            uint64_t temp = 0;
            uint64_t quotient = (uint64_t)e / phi_n;

            temp = e;

            e = phi_n;
            phi_n = temp - quotient * phi_n;

            temp = old_x;

            old_x = x;
            x = temp - quotient * x;

            temp = old_y;

            old_y = y;
            y = temp - quotient * y;
        }

        if (old_x >= 0)
        {
            return old_x;
        }

        return old_x + phi_aux;
    }

    /**
     * @brief Generates a new RSA encryptable object.
     *
     * @param primes Primes list to get a random number from
     * @return RSAEncryption Encryptable object to encrypt and decrypt messages.
     */
    RSAEncryption RSAKey::from(std::vector<uint64_t> &primes)
    {
        auto keys = RSAKey::generate_keys(primes);

        RSAStaticKey public_key = RSAStaticKey(keys[0], keys[2]);
        RSAStaticKey private_key = RSAStaticKey(keys[1], keys[2]);

        return RSAEncryption(public_key, private_key);
    }
}
