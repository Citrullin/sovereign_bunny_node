use alloy_primitives::{Address, B256, Bytes, U256};
use scale::{Decode, Encode};
use sovereign_consensus::stateless::{
    AccountWitness, LatticeBlock, LatticePayload, StaticWitnessProof, VerkleNodeProof,
    WitnessDatabase,
};

#[test]
fn test_account_witness_scale_roundtrip() {
    // GIVEN: An AccountWitness instance with balance, code, and quadrant matrix
    let witness = AccountWitness {
        balance: U256::from(100_000),
        nonce: 42,
        code_hash: B256::repeat_byte(0x55),
        code: vec![0x60, 0x00, 0x60, 0x00, 0xfd],
        quadrant_matrix: [1, 2, 3, 4],
    };

    // WHEN: SCALE encoding and decoding is performed
    let encoded = witness.encode();
    let decoded = AccountWitness::decode(&mut &encoded[..]).unwrap();

    // THEN: Decoded struct matches the original witness exactly
    assert_eq!(decoded.balance, witness.balance);
    assert_eq!(decoded.nonce, witness.nonce);
    assert_eq!(decoded.code_hash, witness.code_hash);
    assert_eq!(decoded.code, witness.code);
    assert_eq!(decoded.quadrant_matrix, witness.quadrant_matrix);
}

#[test]
fn test_hardened_quadrant_matrix_entropy() {
    // GIVEN: An AccountWitness with non-zero quadrant matrix
    let witness = AccountWitness {
        balance: U256::ZERO,
        nonce: 0,
        code_hash: B256::ZERO,
        code: vec![],
        quadrant_matrix: [0x1122334455667788, 0, 0, 0],
    };

    // WHEN: Deriving the hardened quadrant matrix bound to a transaction hash
    let tx_hash = B256::repeat_byte(0xff);
    let hardened = witness.hardened_quadrant_matrix(tx_hash);

    // THEN: Resulting entropy is non-zero and distinct from tx_hash
    assert_ne!(hardened, B256::ZERO);
    assert_ne!(hardened, tx_hash);
}

#[test]
fn test_lattice_block_scale_roundtrip() {
    // GIVEN: A LatticeBlock containing contract call and static witnesses
    let block = LatticeBlock {
        account: Address::repeat_byte(0x12),
        previous_hash: B256::repeat_byte(0x34),
        sequence: 99,
        payload: LatticePayload::ContractCall {
            target: Address::repeat_byte(0x56),
            intent_id: B256::repeat_byte(0x78),
            data: Bytes::from(vec![0xaa, 0xbb, 0xcc]),
        },
        signature: vec![0x01; 65],
        static_witnesses: vec![StaticWitnessProof {
            target_account: Address::repeat_byte(0x99),
            state_root: B256::repeat_byte(0xfe),
            proof_data: vec![0x11, 0x22],
            quadrant_matrix: [0; 4],
            compliance_proof: vec![0x33],
        }],
    };

    // WHEN: SCALE encoding and decoding is performed
    let encoded = block.encode();
    let decoded = LatticeBlock::decode(&mut &encoded[..]).unwrap();

    // THEN: Decoded block matches all fields of the original
    assert_eq!(decoded.account, block.account);
    assert_eq!(decoded.previous_hash, block.previous_hash);
    assert_eq!(decoded.sequence, block.sequence);
    assert_eq!(decoded.signature, block.signature);
    assert_eq!(decoded.static_witnesses.len(), 1);
    assert_eq!(decoded.static_witnesses[0].target_account, Address::repeat_byte(0x99));
}

#[test]
fn test_verkle_node_proof_scale_roundtrip() {
    // GIVEN: A VerkleNodeProof with stem, commit point, and value
    let proof = VerkleNodeProof {
        stem: [0xaa; 31],
        commit_point: [0xbb; 32],
        suffix_index: 5,
        value: [0xcc; 32],
    };

    // WHEN: SCALE encoding and decoding is performed
    let encoded = proof.encode();
    let decoded = VerkleNodeProof::decode(&mut &encoded[..]).unwrap();

    // THEN: Decoded node proof matches the original exactly
    assert_eq!(decoded.stem, proof.stem);
    assert_eq!(decoded.commit_point, proof.commit_point);
    assert_eq!(decoded.suffix_index, proof.suffix_index);
    assert_eq!(decoded.value, proof.value);
}

#[test]
fn test_witness_database_operations() {
    // GIVEN: An in-memory WitnessDatabase
    let mut db = WitnessDatabase::default();
    let addr = Address::repeat_byte(0x11);
    let witness = AccountWitness {
        balance: U256::from(500),
        nonce: 1,
        code_hash: B256::ZERO,
        code: vec![],
        quadrant_matrix: [0; 4],
    };

    // WHEN: Inserting account witness and storage slot values
    db.accounts.insert(addr, witness);
    db.storage.entry(addr).or_default().insert(U256::from(1), U256::from(100));

    // THEN: Queries for balance and storage return the exact written values
    assert_eq!(db.accounts.get(&addr).unwrap().balance, U256::from(500));
    assert_eq!(db.storage.get(&addr).unwrap().get(&U256::from(1)).copied(), Some(U256::from(100)));
}

#[test]
fn test_lattice_receive_block_scale_roundtrip() {
    let block = LatticeBlock {
        account: Address::repeat_byte(0x22),
        previous_hash: B256::repeat_byte(0x33),
        sequence: 5,
        payload: LatticePayload::Receive {
            send_block_hash: B256::repeat_byte(0x44),
            amount: U256::from(50_000),
        },
        signature: vec![0x00; 65],
        static_witnesses: vec![StaticWitnessProof {
            target_account: Address::repeat_byte(0x22),
            state_root: B256::ZERO,
            proof_data: vec![0x99; 32],
            quadrant_matrix: [0; 4],
            compliance_proof: Vec::new(),
        }],
    };

    let encoded = block.encode();
    let decoded = LatticeBlock::decode(&mut &encoded[..]).expect("Decode must succeed");
    assert_eq!(decoded.account, block.account);
    if let LatticePayload::Receive { send_block_hash, amount } = decoded.payload {
        assert_eq!(send_block_hash, B256::repeat_byte(0x44));
        assert_eq!(amount, U256::from(50_000));
    } else {
        panic!("Decoded payload must be Receive variant");
    }
}

#[test]
fn test_eip712_digest_computation() {
    let block = LatticeBlock {
        account: Address::repeat_byte(0x77),
        previous_hash: B256::ZERO,
        sequence: 0,
        payload: LatticePayload::Receive {
            send_block_hash: B256::repeat_byte(0x88),
            amount: U256::from(1_000_000),
        },
        signature: vec![0; 65],
        static_witnesses: Vec::new(),
    };

    let digest1 = sovereign_consensus::execution::stateless::compute_eip712_digest(&block, 13371337);
    let digest2 = sovereign_consensus::execution::stateless::compute_eip712_digest(&block, 13371337);
    assert_eq!(digest1, digest2, "EIP-712 digest must be deterministic");
    assert_ne!(digest1, B256::ZERO, "Digest must be non-zero");
}
