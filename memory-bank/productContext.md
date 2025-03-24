# Product Context: nftbk

## Problem Statement

NFTs (Non-Fungible Tokens) represent digital assets on blockchain networks, but the actual content and metadata associated with these tokens are often stored elsewhere - either on centralized servers, IPFS, or other decentralized storage systems. This creates several challenges:

1. **Persistence Risk**: If hosting services shut down or links break, the content associated with an NFT may become inaccessible, even though the token itself remains on the blockchain.

2. **Gateway Dependency**: Content stored on IPFS often relies on public gateways that can experience downtime, rate limiting, or complete shutdown.

3. **Format Fragmentation**: Different NFT standards and platforms use varying metadata formats and content storage approaches, making comprehensive backups challenging.

4. **Content Complexity**: Modern NFTs can include complex content like HTML pages with embedded resources, interactive elements, or multi-file components that require special handling to preserve completely.

## Solution

nftbk addresses these challenges by providing a robust, chain-agnostic tool for backing up both the metadata and content of NFTs. It ensures collectors can maintain permanent access to their digital assets regardless of the state of third-party services.

### Key Value Propositions

1. **Complete Preservation**: nftbk doesn't just save the metadata JSON - it recursively downloads all linked content, including images, videos, animations, and even embedded resources in HTML-based NFTs.

2. **Multi-Chain Support**: The tool works across different blockchain ecosystems, currently supporting Ethereum-based chains and Tezos, with an architecture designed for extensibility.

3. **Format Handling**: nftbk understands various NFT metadata formats and standards, handling the differences between ERC-721, ERC-1155, and Tezos FA2 tokens appropriately.

4. **Simplified Configuration**: Integration with gallery.so makes it easy to generate backup configurations for entire collections without manually identifying contract addresses and token IDs.

## User Experience Goals

1. **Simplicity**: Users should be able to back up their NFTs with minimal configuration and technical knowledge.

2. **Reliability**: The tool should handle network issues, rate limiting, and other common problems when fetching content from various sources.

3. **Transparency**: Clear logging and feedback should keep users informed about the backup process and any issues encountered.

4. **Flexibility**: Advanced users should have options to customize output locations, logging verbosity, and other parameters.

## Target Users

1. **NFT Collectors**: Individuals who want to ensure long-term access to their digital collections.

2. **Digital Archivists**: People concerned with preserving digital art and cultural artifacts.

3. **NFT Creators**: Artists and developers who want to maintain backups of their created works.

4. **Platform Operators**: NFT marketplace or gallery operators who want to offer backup services to their users.

## Use Cases

1. **Personal Collection Backup**: An individual collector backing up their personal NFT collection for safekeeping.

2. **Gallery Export**: A gallery.so user exporting and backing up a curated gallery of NFTs.

3. **Project Archiving**: An NFT project creator preserving all tokens from their collection.

4. **Offline Viewing**: Creating local copies of NFTs for viewing without blockchain connectivity.
