// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ZkTlsVerifier
/// @notice On-chain Groth16 verifier for zkTLS proofs. Uses a single
///         universal verification key — all schemas share the same circuit.
///         The bn254 pairing precompile (address 0x08) is used for
///         verification.
///
/// @dev The verification key is stored as a packed byte array:
///        - alpha  (G1 point, 64 bytes)
///        - beta   (G2 point, 128 bytes)
///        - gamma  (G2 point, 128 bytes)
///        - delta  (G2 point, 128 bytes)
///        - IC     (variable-length array of G1 points, 64 bytes each)
///      The number of IC elements is derived from (vk.length - 448) / 64.
///      The pairing check uses the standard snarkjs-generated verifier layout.
contract ZkTlsVerifier {
    // Scalar field size
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 internal constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // =========================================================
    //  State
    // =========================================================

    /// @notice The universal zkTLS verification key (one for all schemas).
    bytes public verificationKey;

    /// @notice Whether the verification key has been set.
    bool public vkSet;

    /// @notice proof hash → whether it has been verified (replay protection).
    mapping(bytes32 => bool) public verifiedProofs;

    /// @notice Address of the TaskContract (set after deployment).
    address public taskContract;

    // =========================================================
    //  Events
    // =========================================================

    event VerificationKeySet(uint256 timestamp);
    event ProofVerified(
        bytes32 indexed proofHash,
        bool success,
        uint256 timestamp
    );
    event TaskContractSet(address indexed task, uint256 timestamp);

    // =========================================================
    //  Errors
    // =========================================================

    error ZkTlsVerifier__InvalidVKLength();
    error ZkTlsVerifier__InvalidProofLength();
    error ZkTlsVerifier__InvalidPublicInputs();
    error ZkTlsVerifier__ProofAlreadyVerified();
    error ZkTlsVerifier__VKNotSet();
    error ZkTlsVerifier__PairingCheckFailed();
    error ZkTlsVerifier__NotTaskContract();
    error ZkTlsVerifier__TaskContractAlreadySet();
    error ZkTlsVerifier__VKAlreadySet();

    // =========================================================
    //  Modifiers
    // =========================================================

    modifier onlyTaskContract() {
        if (msg.sender != taskContract) revert ZkTlsVerifier__NotTaskContract();
        _;
    }

    // =========================================================
    //  Admin
    // =========================================================

    function setTaskContract(address _task) external {
        if (taskContract != address(0))
            revert ZkTlsVerifier__TaskContractAlreadySet();
        if (_task == address(0)) revert ZkTlsVerifier__NotTaskContract();
        taskContract = _task;
        emit TaskContractSet(_task, block.timestamp);
    }

    // =========================================================
    //  Verification Key Management
    // =========================================================

    function setVerificationKey(bytes calldata vk) external {
        if (vkSet) revert ZkTlsVerifier__VKAlreadySet();
        _validateVK(vk);
        verificationKey = vk;
        vkSet = true;
        emit VerificationKeySet(block.timestamp);
    }

    // =========================================================
    //  Proof Verification
    // =========================================================

    /// @notice Verify a Groth16 zkTLS proof against the universal VK.
    ///         Only callable by the TaskContract.
    /// @param proof The Groth16 proof (A G1, B G2, C G1 = 256 bytes).
    /// @param publicInputs The public inputs to the proof (ABI-encoded uint256[]).
    /// @return valid Whether the proof is valid.
    function verify(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external onlyTaskContract returns (bool valid) {
        if (!vkSet) revert ZkTlsVerifier__VKNotSet();

        bytes32 proofHash = keccak256(proof);
        if (verifiedProofs[proofHash])
            revert ZkTlsVerifier__ProofAlreadyVerified();

        if (proof.length != 256) revert ZkTlsVerifier__InvalidProofLength();

        bytes memory vk = verificationKey;
        uint256 vkLen = vk.length;
        uint256 icCount = (vkLen - 448) / 64;

        uint256[] memory inputs;
        if (publicInputs.length > 0) {
            inputs = abi.decode(publicInputs, (uint256[]));
        } else {
            inputs = new uint256[](0);
        }

        if (icCount == 0 || inputs.length != icCount - 1)
            revert ZkTlsVerifier__InvalidPublicInputs();

        // Verify using snarkjs-style assembly
        valid = _verifyInAssembly(vk, proof, inputs);

        if (valid) {
            verifiedProofs[proofHash] = true;
        }

        emit ProofVerified(proofHash, valid, block.timestamp);
    }

    // =========================================================
    //  Internal: Assembly Verifier (snarkjs-style)
    // =========================================================

    function _verifyInAssembly(
        bytes memory vk,
        bytes calldata proof,
        uint256[] memory inputs
    ) internal view returns (bool) {
        bool isValid;

        assembly {
            // Memory layout (matching snarkjs convention):
            //   pMem       = free memory pointer
            //   pVk        = pMem + 0   (64 bytes for vk_x accumulator)
            //   pPairing   = pMem + 128 (768 bytes for pairing input)
            //   pLastMem   = 896

            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(
                pMem,
                vkBytesPtr,
                proofOffset,
                inputsPtr,
                inputsLen
            ) -> isOk {
                let _pPairing := add(pMem, 128)
                let _pVk := add(pMem, 0)

                // --- Load IC[0] as initial vk_x ---
                // vk layout: alpha(64) | beta(128) | gamma(128) | delta(128) | IC[0](64) | IC[1](64) | ...
                // IC[0] starts at offset 448
                let ic0Offset := add(vkBytesPtr, 448)
                mstore(_pVk, mload(ic0Offset))
                mstore(add(_pVk, 32), mload(add(ic0Offset, 32)))

                // --- Compute vk_x = IC[0] + sum(IC[i+1] * pubSignal[i]) ---
                // inputs is a uint256[] memory: [offset, length, values...]
                // inputsPtr points to the start of the array data
                // inputsLen is at inputsPtr, values start at inputsPtr + 32
                let inputValuesPtr := add(inputsPtr, 32)
                for {
                    let i := 0
                } lt(i, inputsLen) {
                    i := add(i, 1)
                } {
                    let pubVal := mload(add(inputValuesPtr, mul(i, 32)))
                    if iszero(iszero(pubVal)) {
                        // Load IC[i+1] from vk at offset 448 + 64 * (i + 1)
                        let icOffset := add(
                            vkBytesPtr,
                            add(448, mul(add(i, 1), 64))
                        )
                        let icX := mload(icOffset)
                        let icY := mload(add(icOffset, 32))
                        g1_mulAccC(_pVk, icX, icY, pubVal)
                    }
                }

                // --- Build pairing input (snarkjs layout) ---

                // Pair 1: (-A, B)
                // -A: negate A.y
                mstore(_pPairing, calldataload(proofOffset))
                mstore(
                    add(_pPairing, 32),
                    mod(sub(Q, calldataload(add(proofOffset, 32))), Q)
                )

                // B: [b1.x, b1.y, b2.x, b2.y] = [x_im, x_re, y_im, y_re]
                mstore(add(_pPairing, 64), calldataload(add(proofOffset, 64)))
                mstore(add(_pPairing, 96), calldataload(add(proofOffset, 96)))
                mstore(add(_pPairing, 128), calldataload(add(proofOffset, 128)))
                mstore(add(_pPairing, 160), calldataload(add(proofOffset, 160)))

                // Pair 2: (alpha, beta)
                // alpha at vk offset 0
                mstore(add(_pPairing, 192), mload(add(vkBytesPtr, 0)))
                mstore(add(_pPairing, 224), mload(add(vkBytesPtr, 32)))

                // beta at vk offset 64: [x_im, x_re, y_im, y_re]
                mstore(add(_pPairing, 256), mload(add(vkBytesPtr, 64)))
                mstore(add(_pPairing, 288), mload(add(vkBytesPtr, 96)))
                mstore(add(_pPairing, 320), mload(add(vkBytesPtr, 128)))
                mstore(add(_pPairing, 352), mload(add(vkBytesPtr, 160)))

                // Pair 3: (vk_x, gamma)
                mstore(add(_pPairing, 384), mload(_pVk))
                mstore(add(_pPairing, 416), mload(add(_pVk, 32)))

                // gamma at vk offset 192: [x_im, x_re, y_im, y_re]
                mstore(add(_pPairing, 448), mload(add(vkBytesPtr, 192)))
                mstore(add(_pPairing, 480), mload(add(vkBytesPtr, 224)))
                mstore(add(_pPairing, 512), mload(add(vkBytesPtr, 256)))
                mstore(add(_pPairing, 544), mload(add(vkBytesPtr, 288)))

                // Pair 4: (C, delta)
                mstore(add(_pPairing, 576), calldataload(add(proofOffset, 192)))
                mstore(add(_pPairing, 608), calldataload(add(proofOffset, 224)))

                // delta at vk offset 320: [x_im, x_re, y_im, y_re]
                mstore(add(_pPairing, 640), mload(add(vkBytesPtr, 320)))
                mstore(add(_pPairing, 672), mload(add(vkBytesPtr, 352)))
                mstore(add(_pPairing, 704), mload(add(vkBytesPtr, 384)))
                mstore(add(_pPairing, 736), mload(add(vkBytesPtr, 416)))

                // Call bn254 pairing precompile
                let success := staticcall(
                    sub(gas(), 2000),
                    8,
                    _pPairing,
                    768,
                    _pPairing,
                    0x20
                )
                isOk := and(success, mload(_pPairing))
            }

            // --- Main verification ---

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, 896))

            // vk is a bytes memory: [length(32), data...]
            // vkBytesPtr points to the start of the vk data
            let vkBytesPtr := add(vk, 32)

            // proof is bytes calldata: proof.offset points to the data
            let proofOffset := proof.offset

            // inputs is a uint256[] memory: [offset(32), length(32), values...]
            // inputsPtr points to the start of the array metadata
            let inputsPtr := inputs
            let inputsLen := mload(inputsPtr)

            isValid := checkPairing(
                pMem,
                vkBytesPtr,
                proofOffset,
                inputsPtr,
                inputsLen
            )

            mstore(0x40, pMem)
        }

        return isValid;
    }

    // =========================================================
    //  Internal: VK Validation
    // =========================================================

    function _validateVK(bytes calldata vk) internal pure {
        if (vk.length < 448 || (vk.length - 448) % 64 != 0) {
            revert ZkTlsVerifier__InvalidVKLength();
        }
    }

    // =========================================================
    //  View Functions
    // =========================================================

    function isProofVerified(bytes32 proofHash) external view returns (bool) {
        return verifiedProofs[proofHash];
    }
}
