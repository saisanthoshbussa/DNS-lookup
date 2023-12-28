# DNS Lookup Tool

This program is a simple DNS lookup tool implemented in C++, allowing users to convert domain names into their corresponding IP addresses using basic networking and socket programming concepts.

## Description

The program follows these steps:
1. Takes a domain name as input from the user.
2. Establishes a UDP socket connection to a DNS server (Google's public DNS server: 8.8.8.8, port 53).
3. Crafts a DNS query packet using the DNS message format.
4. Sends the query to the DNS server and awaits a response.
5. Parses the DNS response packet and extracts the IP address(es) associated with the provided domain name.
6. Prints the IP address(es) to the console.

### DNS Message Format

The DNS query packet consists of several sections:
- Header
- Question
- Answer
- Authority
- Additional

![dns](https://github.com/saisanthoshbussa/DNS-lookup/assets/118352633/02390a0d-26a0-42a6-a9f2-4eb58f4db12e)


### Caching Mechanism

The program implements a caching mechanism using a `map` to store DNS responses for previously queried domain names. This caching improves lookup speed by retrieving IP addresses from the cache instead of querying the DNS server again.

### Prerequisites

- This program uses C++ and standard libraries. No external dependencies are required.
- Compile the source code using a C++ compiler (`g++`, `clang++`, etc.).

### Running the Program

1. Clone the repository containing the source code.
2. Compile the code using a C++ compiler.
   ```sh
   g++ -o dns_lookup dns_lookup.cpp
