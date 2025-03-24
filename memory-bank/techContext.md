# Technical Context: nftbk

## Technology Stack

### Programming Language
- **Rust**: The entire application is written in Rust, chosen for its performance, memory safety, and robust error handling.

### Core Dependencies

#### Blockchain Interaction
- **alloy**: Modern Ethereum library for interacting with EVM-based chains
- **tezos-core**, **tezos-rpc**, **tezos-contract**: Libraries for Tezos blockchain interaction
- **hex**: For encoding/decoding hexadecimal data from blockchain responses

#### Asynchronous Runtime
- **tokio**: Async runtime for handling concurrent operations
- **futures**: Additional utilities for async programming

#### HTTP and Content Fetching
- **reqwest**: HTTP client for fetching content from web servers and IPFS gateways
- **url**: URL parsing and manipulation
- **base64**: Decoding base64-encoded content from data URLs

#### Data Parsing and Serialization
- **serde**: Serialization/deserialization framework
- **serde_json**: JSON parsing and generation
- **toml**: Configuration file parsing
- **scraper**: HTML parsing for extracting embedded resources

#### CLI and User Interface
- **clap**: Command-line argument parsing with rich features
- **tracing**: Structured, contextual logging
- **tracing-subscriber**: Configurable logging output

#### Error Handling
- **anyhow**: Flexible error handling with context

#### Utilities
- **flate2**: Compression/decompression for handling gzipped content

## Development Environment

### Build System
- **Cargo**: Rust's package manager and build system
- **rustfmt**: Code formatting tool
- **clippy**: Linting tool for catching common mistakes and enforcing style

### Version Control
- **Git**: Source code version control
- **Pre-commit hooks**: Automated checks before committing code

## External Services

### Blockchain RPC Providers
- Support for configurable RPC endpoints for each blockchain
- Examples include:
  - Ethereum: Infura, Alchemy, or self-hosted nodes
  - Tezos: SmartPy, TzKT, or self-hosted nodes
  - Other EVM chains: Chain-specific RPC providers

### IPFS Gateways
- Default gateway: ipfs.io
- Architecture supports using alternative gateways

### NFT Metadata Sources
- Direct blockchain queries for token URIs
- Support for various metadata hosting services:
  - IPFS
  - Centralized servers
  - Arweave (via HTTP gateway)

## Technical Constraints

### Performance Considerations
- **Rate Limiting**: Many RPC providers and content hosts impose rate limits
- **Network Latency**: Content fetching is network-bound
- **Concurrency**: Balancing concurrent requests to avoid overwhelming services

### Security Considerations
- **API Keys**: Handling of sensitive RPC provider API keys
- **Content Safety**: Dealing with potentially malicious content in NFTs

### Compatibility
- **NFT Standards**: Supporting various token standards (ERC-721, ERC-1155, FA2)
- **Metadata Formats**: Handling different metadata schemas across platforms
- **Content Types**: Supporting diverse media formats and storage methods

## Technical Debt and Limitations

### Current Limitations
- No parallel processing of multiple tokens (sequential processing only)
- Single IPFS gateway with no fallback mechanism
- Limited special case handling for unique NFT implementations

### Future Technical Considerations
- Implementing concurrent token processing for performance
- Adding IPFS gateway rotation and fallbacks
- Supporting additional blockchains (Solana, Flow, etc.)
- Adding content verification mechanisms
