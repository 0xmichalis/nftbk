# Project Brief: nftbk

## Overview
nftbk is a CLI tool designed to back up NFT metadata and content from Ethereum and Tezos NFT contracts. It allows users to preserve their NFT collections by downloading and storing all associated metadata and media files locally.

## Core Requirements

1. **Multi-Chain Support**
   - Back up NFTs from Ethereum-based chains (Ethereum, Zora, Base, Arbitrum)
   - Back up NFTs from Tezos blockchain
   - Extensible architecture to potentially support additional chains

2. **Content Preservation**
   - Download and store NFT metadata (JSON)
   - Download and store NFT media files (images, videos, animations, 3D models)
   - Handle various content types and formats
   - Support for IPFS content through gateways
   - Process HTML content and download embedded resources

3. **Configuration**
   - Support for configuration via TOML files
   - Ability to specify RPC endpoints for different chains
   - Ability to specify token contracts and IDs to back up
   - Integration with gallery.so for easy token extraction

4. **User Experience**
   - Simple command-line interface
   - Configurable output paths
   - Adjustable logging levels
   - Clear feedback on backup progress and completion

## Project Goals

1. **Data Preservation**: Ensure NFT collectors can maintain permanent access to their digital assets regardless of the state of third-party services or blockchain infrastructure.

2. **Completeness**: Capture all relevant data and files associated with NFTs, including metadata, images, animations, and other linked content.

3. **Reliability**: Handle various edge cases in NFT metadata formats and content storage methods across different blockchains.

4. **Performance**: Efficiently process multiple NFTs with appropriate error handling and retry mechanisms.

## Non-Goals

1. **Web Interface**: The tool is designed as a CLI application only, with no plans for a web or GUI version.

2. **NFT Creation/Minting**: This is strictly a backup tool, not for creating or minting NFTs.

3. **Marketplace Features**: No buying, selling, or trading functionality.

4. **Real-time Syncing**: This is a point-in-time backup tool, not a continuous syncing solution.
