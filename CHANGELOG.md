## 0.5.0 - 2023-3-16

### Added
 - `90s-fixslice` feature, using RustCrypto's AES implementation
 - More key exchange testing (thanks Francesco Medina)
 - Examples

### Changed
- Bumped dependencies

### Fixed
- Documentation

### Removed
 - Unnecessary sha2 default dependencies

## 0.4.0 - 2023-1-18

### Added
- Hazmat feature flag to expose Kyber primitives
- NASM assembly code for better portability
- CI runners for macOS and Windows
- CI runners on tier 2 targets
- Big endian testing
- Error implementation

### Changed
- Bumped dependencies
- Zeroise feature to Zeroize, no more British English in features 

### Fixed
- Documentation
- Various CI issues
