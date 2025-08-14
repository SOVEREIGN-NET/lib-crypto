[
Ring signiture currently uses Curve25519 via curve25519_dalek library, Ristretto points on Curve25519 for group operations, and Ed25519 keys for compatibility within the ring.
The Problem: Cryptographic Inconsistency
ZHTP's Mixed Approach:

Post-Quantum: CRYSTALS-Dilithium (signatures) + CRYSTALS-Kyber (KEM)
Classical: Curve25519/Ed25519 for ring signatures
Result: The ring signatures are NOT quantum-resistant

proposed fix 
1. Post-quantum group signature schemes (lattice-based)
2. ZK-SNARK based anonymity (which ZHTP already has with Plonky2(zkps still needs to be properly implemented - see zk))
3. Hybrid approach with quantum-safe anonymity sets
]

