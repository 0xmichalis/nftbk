# Active Context: nftbk

## Current Work Focus

The project is currently in a functional state with the following capabilities:

1. **Multi-Chain Support**: 
   - Ethereum-based chains (Ethereum, Zora, Base, Arbitrum)
   - Tezos blockchain

2. **Content Handling**:
   - Metadata retrieval and storage
   - Media file downloading (images, videos, animations)
   - HTML content processing with embedded resource extraction
   - Special case handling for specific NFT contracts

3. **Configuration**:
   - TOML-based configuration
   - Gallery.so integration for easy token extraction

## Recent Changes

The most recent work has focused on:

1. **Code Organization**: 
   - Modular architecture with clear separation of concerns
   - Chain-specific implementations isolated in dedicated modules

2. **Error Handling**:
   - Improved error reporting and logging
   - Retry mechanisms for rate-limited API calls

3. **Content Processing**:
   - Enhanced media type detection
   - Support for various URL formats and protocols

## Active Decisions

1. **Sequential Processing**:
   - Currently, tokens are processed sequentially rather than concurrently
   - This approach simplifies error handling and reduces the risk of rate limiting
   - Future work may introduce controlled concurrency for performance improvements

2. **IPFS Gateway Strategy**:
   - Currently using ipfs.io as the default gateway
   - Considering implementing gateway rotation or fallback mechanisms
   - Evaluating the trade-offs between reliability and complexity

3. **Extension Mechanism**:
   - Current approach uses pattern matching on contract addresses and token IDs
   - Evaluating more flexible approaches for special case handling

## Next Steps

The following areas are being considered for future development:

1. **Performance Improvements**:
   - Implementing controlled concurrency for token processing
   - Adding progress tracking for long-running backups

2. **Reliability Enhancements**:
   - IPFS gateway rotation and fallbacks
   - Resumable downloads for interrupted backups

3. **Feature Additions**:
   - Support for additional blockchains (Solana, Flow, etc.)
   - Content verification mechanisms
   - Incremental/differential backups

4. **User Experience**:
   - More detailed progress reporting
   - Summary statistics after backup completion

## Current Challenges

1. **Rate Limiting**:
   - Many RPC providers and content hosts impose rate limits
   - Need to balance performance with reliability

2. **Content Diversity**:
   - NFTs use a wide variety of content storage approaches
   - Ensuring comprehensive coverage of all formats and storage methods

3. **Metadata Standards**:
   - Different platforms use varying metadata schemas
   - Need to handle these differences while maintaining a consistent backup structure
