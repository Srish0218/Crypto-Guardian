﻿# CryptoGuardian 🛡️️

CryptoGuardian is a user-friendly Streamlit app offering powerful hashing functionalities for data integrity and security. This app supports various hash algorithms, allows users to compare hashes, and provides additional features like password hashing.

[![View Demo](https://img.shields.io/badge/View-Demo-blueviolet)](https://srish0218-cryptoguardian.streamlit.app/) [![GitHub issues](https://img.shields.io/github/issues/Srish0218/CryptoGuardian)](https://github.com/Srish0218/CryptoGuardian/issues) [![GitHub license](https://img.shields.io/github/license/Srish0218/CryptoGuardian)](LICENSE.md)

## Features

### 1. Hashing Data
- **String Input:** Enter a string and select a hash algorithm to generate the hash.
- **File Upload:** Upload a file to generate hashes based on the selected hash algorithms.

### 2. Compare Hashing
- Compare two hash values to verify data integrity.
- The application generates a heatmap visualization to show the similarity between the two hash values and a comparison of the frequency of characters in each hash value.

- **Heatmap Visualization:** The heatmap provides a graphical representation of the similarity between the 
characters of two hash values. Each cell in the heatmap represents the comparison between a character from Hash 1 and 
a character from Hash 2.

- **Color Gradient:** The colors in the heatmap represent the level of similarity between characters:

    - Cells with a value of 1 are colored in the darkest shade, indicating an exact match between characters.
    - Cells with a value of 0 are colored in the lightest shade, indicating no match between characters.
- **Axes:** The heatmap has two axes:

    - The x-axis represents the characters of Hash 2.
    - The y-axis represents the characters of Hash 1.
***Possible Outputs:***

- **Perfect Match:** If both hash values are identical, the heatmap will show a diagonal line of dark-colored 
    cells from the top-left corner to the bottom-right corner. This indicates that each character in Hash 1 matches 
    the corresponding character in Hash 2.

- **Partial Match:** If some characters match but not all, the heatmap will show dark-colored cells clustered 
    along the diagonal line, indicating matching characters. The remaining cells will be light-colored, indicating 
    non-matching characters.

- **No Match:** If none of the characters match between the two hash values, the heatmap will be entirely 
    light-colored, indicating no similarity between the hash values.
### 3. Additional Features
- **Password Hashing:** Hash passwords using the SHA-256 algorithm.

### 4. Visualization
- **Hash Lengths:** Visualize the bit lengths of different hash algorithms.
- **Algorithm Distribution:** Show the popularity distribution of hash algorithms within the application.
- **Historical Hashing:** Display changes in hash values over time for each algorithm.
- **Radar Chart:** Compare hash algorithms based on attributes like speed, security, flexibility, and collision resistance.
- **Hash Collisions:** Present a heatmap indicating the likelihood of collisions between hash algorithms.
- **Hash Digests:** Utilize doughnut charts to illustrate the distribution of hash digest components for each algorithm.

> ***Disclaimer***
> 
> The visualizations on this page use a combination of real-world data and simulated data for illustrative purposes. When interpreting the results, keep in mind that actual hash algorithm characteristics may vary based on specific benchmarks and real-world scenarios. Explore and enjoy the visual journey through the world of hash algorithms with CryptoGuardian!

## Supported Hash Algorithms
- SHA-256
- SHA-384
- SHA-224
- SHA-512
- SHA-1
- MD5
- SHA3-256
- SHA3-512
- BLAKE2b
- BLAKE2s

### Overview of Hash Algorithms:

**1. What is a Hash Function?**
A hash function is a mathematical algorithm that takes an input (or 'message') and produces a fixed-size string of characters, which is typically a hash code. The output, or hash, is unique to the input data, and even a small change in the input should result in a significantly different hash.

**2. Purpose of Hash Functions:**
Hash functions serve various purposes, including data integrity verification, digital signatures, password storage, and, notably, in the context of blockchain, ensuring the integrity of blocks and creating unique identifiers for transactions.

### SHA-2 Family:

> SHA-2 is a family of hash functions with different bit lengths: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. The number in each name denotes the length of the hash output in bits.
The SHA (Secure Hash Algorithm) family consists of several hash functions designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST). Here's an overview of the commonly used members of the SHA family:

1. **SHA-1 (Secure Hash Algorithm 1):**
   - **Output Size:** 160 bits (20 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - SHA-1 was widely used for cryptographic applications and digital signatures. However, vulnerabilities were discovered, and collision attacks demonstrated its weakness. As a result, SHA-1 is deprecated for cryptographic use, and more secure alternatives are recommended.

2. **SHA-224 (Secure Hash Algorithm 224):**
   - **Output Size:** 224 bits (28 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - SHA-224 is a truncated version of SHA-256, providing a shorter hash value. It is suitable for applications where a shorter hash is needed while maintaining a reasonable level of security.

3. **SHA-256 (Secure Hash Algorithm 256):**
   - **Output Size:** 256 bits (32 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - SHA-256 is part of the SHA-2 family and is widely used in various cryptographic applications, including blockchain technology. It provides a good balance between security and efficiency and is considered secure for most purposes.

4. **SHA-384 (Secure Hash Algorithm 384):**
   - **Output Size:** 384 bits (48 bytes)
   - **Internal Block Size:** 1024 bits (128 bytes)
   - SHA-384 is a truncated version of SHA-512, offering a longer hash value for applications that require increased security. It is commonly used in digital signatures and certificates.

5. **SHA-512 (Secure Hash Algorithm 512):**
   - **Output Size:** 512 bits (64 bytes)
   - **Internal Block Size:** 1024 bits (128 bytes)
   - SHA-512 is another member of the SHA-2 family, providing a higher level of security due to its longer hash size. It is suitable for applications requiring strong cryptographic protection.

**Common Characteristics:**
- All SHA algorithms in the SHA-2 family operate on blocks of data with an internal block size of 512 or 1024 bits.
- The output size of the SHA algorithms can be configured to produce hash values of varying lengths (e.g., SHA-224, SHA-256, SHA-384, SHA-512).

**Usage and Recommendations:**
- SHA-256 is commonly used for various cryptographic applications, including blockchain technology, due to its balance of security and efficiency.
- SHA-3, a separate family of hash functions, is also available and is designed to provide security against certain types of attacks.
- When selecting a SHA algorithm, consider the specific requirements of your application, including the desired level of security and the length of the hash value needed.

### MD Family:

MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value, typically expressed as a 32-character hexadecimal number. MD5 is part of the MD5 family of hash functions, which includes variants like MD2 and MD4. Here's a brief overview of each member of the MD5 family:

1. **MD2 (Message Digest Algorithm 2):**
   - **Output Size:** 128 bits (16 bytes)
   - **Internal Block Size:** 64 bits (8 bytes)
   - MD2 is an earlier version of the MD family and is considered obsolete due to vulnerabilities. It was designed for 8-bit computers but is not recommended for cryptographic purposes today.

2. **MD4 (Message Digest Algorithm 4):**
   - **Output Size:** 128 bits (16 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - MD4 is another early member of the MD family. It is also considered insecure and has been largely replaced by more secure hash functions. MD4 produces a 128-bit hash value.

3. **MD5 (Message Digest Algorithm 5):**
   - **Output Size:** 128 bits (16 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - MD5 is the most well-known member of the MD family. It was widely used for checksums and integrity verification. However, MD5 is now considered cryptographically broken and unsuitable for further use due to vulnerabilities such as collision attacks.

**Common Characteristics:**
- All three algorithms in the MD5 family produce fixed-size hash values (128 bits or 16 bytes).
- They operate on blocks of data, with different internal block sizes (64 bits for MD2 and MD5, 512 bits for MD4).
- The security of MD2, MD4, and MD5 has been compromised, and they are not recommended for cryptographic applications.

**Usage and Recommendations:**
- While MD2 and MD4 are considered obsolete and insecure, MD5 is still used in non-cryptographic applications, such as checksums for file integrity verification. However, it should not be used for cryptographic purposes where collision resistance is crucial.
- For cryptographic applications and data integrity verification, more secure hash functions like SHA-256 or SHA-3 are recommended.

> It's essential to be aware of the limitations and vulnerabilities of MD2, MD4, and MD5 when considering their use in any context. If security is a primary concern, it's advisable to use modern and widely accepted hash functions.

### BLAKE Family:
The BLAKE family of cryptographic hash functions includes BLAKE2b and BLAKE2s, which are successors to the original BLAKE algorithm. Here's an overview of each member of the BLAKE family:

1. **BLAKE (Original Algorithm):**
   - **Output Size:** Configurable (e.g., BLAKE-256, BLAKE-512)
   - **Internal Block Size:** 512 bits (64 bytes)
   - BLAKE is a cryptographic hash function that is not commonly used compared to its successors, BLAKE2b and BLAKE2s. It is based on the HAIFA construction and uses a ChaCha-like permutation. The output size can be configured for different applications.

2. **BLAKE2b (BLAKE2 for Bytes):**
   - **Output Size:** Configurable (up to 64 bytes)
   - **Internal Block Size:** 1024 bits (128 bytes)
   - BLAKE2b is an improved version of BLAKE designed for parallelism and efficiency on 64-bit platforms. It offers high security, speed, and flexibility. BLAKE2b can generate hash values of various lengths, making it suitable for a wide range of applications, including hash-based message authentication codes (HMAC).

3. **BLAKE2s (BLAKE2 for Short):**
   - **Output Size:** Configurable (up to 32 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - BLAKE2s is an optimized version of BLAKE2 designed for 8- and 32-bit platforms. It provides similar security guarantees as BLAKE2b but is more efficient on resource-constrained devices. BLAKE2s is well-suited for applications with limited memory and processing power.

**Common Characteristics:**
- BLAKE and its successors, BLAKE2b and BLAKE2s, are cryptographic hash functions designed to provide high security.
- Both BLAKE2b and BLAKE2s support variable output sizes, allowing users to generate hash values of different lengths.
- BLAKE2b is optimized for 64-bit platforms, while BLAKE2s is optimized for 8- and 32-bit platforms.

**Usage and Recommendations:**
- The BLAKE family, especially BLAKE2b and BLAKE2s, is widely used in various applications, including data integrity verification, digital signatures, and secure communication protocols.
- BLAKE2b and BLAKE2s are considered secure and efficient, making them suitable for a broad range of platforms and use cases.
- BLAKE2 is often chosen for its simplicity, flexibility, and speed, making it a competitive choice among modern cryptographic hash functions.

> When selecting a hash function from the BLAKE family, the choice between BLAKE2b and BLAKE2s depends on the platform and specific requirements of the application. Both variants offer strong security and performance characteristics.
### Hashing Process:

1. **Encoding:**
   - Before hashing, the input data is encoded into bytes. In the provided Python code, `str1.encode()` converts the string "Krish Naik1" into bytes.

2. **Hash Calculation:**
   - The hash object, such as `hashlib.sha256()`, is initialized with the encoded data.
   - The `update()` method can be used for incremental updates, but in this example, it's not necessary.

3. **Hexadecimal Representation:**
   - The `hexdigest()` method converts the binary hash into a human-readable hexadecimal representation.

### Use Cases:

- **Blockchain:**
  - In blockchain technology, SHA-256 is commonly used to create unique identifiers (hashes) for blocks.
  - The deterministic nature of hash functions ensures that a block's hash changes if any information in the block is modified, maintaining the integrity of the blockchain.

- **Data Integrity:**
  - Hash functions are used to verify the integrity of transmitted or stored data. The recipient can recompute the hash and check if it matches the original hash.

- **Digital Signatures:**
  - Hash functions are an integral part of digital signatures, providing a compact representation of data that is signed for verification purposes.

> In summary, Secure Hash Algorithms play a crucial role in ensuring data integrity, security, and uniqueness in various applications, with SHA-256 being a fundamental component in blockchain technology.
     
## Usage

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/Srish0218/CryptoGuardian.git
    cd CryptoGuardian
    ```

2. **Run the App:**
    ```bash
    python -m streamlit run SHA.py
    ```

3. **Interact with the App:**
    - Select the desired feature ("Hashing Data" or "Compare Hashing").
    - Follow on-screen instructions to input data or upload a file.
    - Generate hashes and explore additional functionalities.

## Demo
View the [live demo](https://srish0218-cryptoguardian.streamlit.app/) to experience CryptoGuardian in action!

## Contributing
Contributions are welcome! If you have ideas for new features or improvements, please feel free to [open an issue](https://github.com/Srish0218/CryptoGuardian/issues) or submit a pull request.

## Troubleshooting
If you encounter any issues, check the [Troubleshooting](docs/TROUBLESHOOTING.md) guide for common problems and solutions.

## License
This project is licensed under the [MIT License](LICENSE.md). Feel free to use and modify it as per your requirements.

## Credits
Developed with ❤ by [Srishti Jaitly](https://github.com/Srish0218).

---

*If you have questions, encounter issues, or want to discuss features, please [open an issue](https://github.com/Srish0218/CryptoGuardian/issues).*

*Thank you for using CryptoGuardian!*

> ### For testing
> Hashing is a fundamental concept in computer science and cryptography, used to securely transform data into a fixed-size string of characters. This process generates a unique digital fingerprint, known as a hash, for any given input. Hash functions are designed to be one-way functions, meaning it is computationally infeasible to reverse-engineer the original input from the hash. This property makes hashing invaluable for various applications such as password storage, data integrity verification, and digital signatures. Common hash algorithms include MD5, SHA-1, and SHA-256, each offering different levels of security and performance. Despite its widespread use, hashing is not immune to vulnerabilities, and collisions (when two different inputs produce the same hash) can occur, highlighting the importance of choosing appropriate hash functions and employing additional security measures when necessary.
