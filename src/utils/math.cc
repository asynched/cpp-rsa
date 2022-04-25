#include "math.h"

#include <bits/stdc++.h>

#include <iostream>
#include <vector>

namespace math {
/**
 * @brief Calculates the the x to the power of y mod z.
 *
 * @param x Base value.
 * @param y Exponent value.
 * @param p Modulus value.
 * @return uint64_t The calculated operation
 */
uint64_t power(uint64_t x, uint64_t y, uint64_t z) {
    uint64_t pow = 1;

    x = x % z;

    if (x == 0) return 0;

    while (y > 0) {
        if (y & 1) pow = (pow * x) % z;

        y = y >> 1;
        x = (x * x) % z;
    }

    return pow;
}

/**
 * @brief Generates a list of primes from 0 to range.
 *
 * @param range Range of primes to be generated.
 * @return std::vector<uint64_t>
 */
std::vector<uint64_t> generate_primes(uint64_t range) {
    std::vector<uint64_t> primes = std::vector<uint64_t>();
    bool prime[range + 1];

    memset(prime, true, sizeof(prime));

    for (uint64_t idx = 2; idx * idx <= range; idx++) {
        if (prime[idx] == true) {
            for (uint64_t i = idx * idx; i <= range; i += idx) prime[i] = false;
        }
    }

    for (uint64_t idx = 2; idx <= range; idx++) {
        if (prime[idx]) {
            primes.push_back(idx);
        }
    }

    return primes;
}
}  // namespace math
