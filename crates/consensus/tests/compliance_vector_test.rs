use alloy_primitives::Address;
use sovereign_consensus::compliance_vector::{bits, compliance_leaf_key, ComplianceVector};

#[test]
fn test_compliance_vector_round_trip() {
    // GIVEN: A 4-quadrant compliance matrix configuration
    let raw = [
        bits::Q0_FROZEN | bits::Q0_VELOCITY_CAP,
        bits::Q1_EU_EEA | bits::Q1_OFAC_SANCTIONED,
        bits::Q2_INSTITUTIONAL | bits::Q2_RFI,
        bits::Q3_DAO_MEMBER | bits::Q3_VALIDATOR,
    ];

    // WHEN: Constructing and serializing the ComplianceVector
    let vec = ComplianceVector::from_quadrant_matrix(raw);
    let bytes = vec.to_bytes();
    let decoded = ComplianceVector::from_bytes(bytes);

    // THEN: Quadrants and serialization match the original matrix exactly
    assert_eq!(vec.to_quadrant_matrix(), raw);
    assert_eq!(decoded, vec);
    assert_eq!(decoded.q0(), raw[0]);
    assert_eq!(decoded.q1(), raw[1]);
    assert_eq!(decoded.q2(), raw[2]);
    assert_eq!(decoded.q3(), raw[3]);
}

#[test]
fn test_subsumes_jurisdiction() {
    // GIVEN: A user allowed in EU/EEA, US SEC/CFTC, and APAC
    let user_allowed = ComplianceVector::from_quadrant_matrix([
        0,
        bits::Q1_EU_EEA | bits::Q1_US_SEC_CFTC | bits::Q1_APAC,
        0,
        0,
    ]);

    let contract_req_eu = ComplianceVector::from_quadrant_matrix([0, bits::Q1_EU_EEA, 0, 0]);
    let contract_req_us = ComplianceVector::from_quadrant_matrix([0, bits::Q1_US_SEC_CFTC, 0, 0]);
    let contract_req_ofac = ComplianceVector::from_quadrant_matrix([0, bits::Q1_OFAC_SANCTIONED, 0, 0]);

    // WHEN: Checking jurisdiction subsumption
    // THEN: EU and US requirements are subsumed, but OFAC sanctioned is not
    assert!(user_allowed.subsumes_jurisdiction(&contract_req_eu));
    assert!(user_allowed.subsumes_jurisdiction(&contract_req_us));
    assert!(!user_allowed.subsumes_jurisdiction(&contract_req_ofac));
}

#[test]
fn test_has_category_overlap() {
    // GIVEN: A retail EOA compliance profile and contract category requirements
    let user = ComplianceVector::from_quadrant_matrix([0, 0, bits::Q2_RETAIL_EOA, 0]);
    let inst_contract = ComplianceVector::from_quadrant_matrix([0, 0, bits::Q2_INSTITUTIONAL, 0]);
    let any_eoa_contract = ComplianceVector::from_quadrant_matrix([0, 0, bits::Q2_RETAIL_EOA | bits::Q2_INSTITUTIONAL, 0]);

    // WHEN: Checking category overlap
    // THEN: Institutional has no overlap, any EOA overlaps successfully
    assert!(!user.has_category_overlap(&inst_contract));
    assert!(user.has_category_overlap(&any_eoa_contract));
}

#[test]
fn test_is_dao_member() {
    // GIVEN: A DAO member compliance vector
    let member = ComplianceVector::from_quadrant_matrix([0, 0, 0, bits::Q3_DAO_MEMBER]);

    // WHEN: Testing membership flags
    // THEN: DAO member returns true, Validator returns false
    assert!(member.is_dao_member(bits::Q3_DAO_MEMBER));
    assert!(!member.is_dao_member(bits::Q3_VALIDATOR));
}

#[test]
fn test_compliance_leaf_key_derivation() {
    // GIVEN: Two distinct EVM addresses
    let addr1 = Address::repeat_byte(0x11);
    let addr2 = Address::repeat_byte(0x22);

    // WHEN: Deriving compliance leaf keys
    let key1 = compliance_leaf_key(&addr1);
    let key2 = compliance_leaf_key(&addr2);

    // THEN: Derived SMT keys are unique and deterministic
    assert_ne!(key1, key2);
    assert_eq!(key1, compliance_leaf_key(&addr1));
}
