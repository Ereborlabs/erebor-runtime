use super::*;

fn id(index: u16, kind: u8) -> [u8; 16] {
    let mut value = [0; 16];
    value[..2].copy_from_slice(&index.to_be_bytes());
    value[2] = kind;
    value
}

fn fixture(
    index: u16,
    issuer: &AuthorityIssuerV1,
    sequence: u64,
) -> (AuthorityLeaseRequestV1, AuthorityIntentPayloadV1) {
    let mut request = request(13);
    request.request_id = id(index, 1);
    request.body.request_nonce = id(index, 2);
    let mut intent = payload(sequence);
    intent.issuer_id = issuer.issuer_id;
    intent.sequence_epoch = issuer.sequence_epoch;
    intent.proof_id = id(index, 3);
    intent.slots = vec![id(index, 4).into()];
    intent.body.lease = request.body.clone();
    (request, intent)
}

fn reject_unchanged(
    store: &ControlStore,
    code: AuthorityErrorCodeV1,
    operation: impl FnOnce() -> Result<AuthorityApprovalV1>,
) -> TestResult {
    let before = store.authority_state()?;
    let revision = store.commit_index();
    assert!(matches!(
        operation(),
        Err(crate::Error::Authority { code: actual, .. }) if actual == code
    ));
    assert_eq!(store.commit_index(), revision);
    assert_eq!(store.authority_state()?, before);
    Ok(())
}

fn alias_key(signed: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = minicbor::Decoder::new(signed);
    decoder.map()?;
    for _ in 0..3 {
        decoder.u8()?;
    }
    assert_eq!(decoder.bytes()?, b"key");
    let end = decoder.position();
    let mut aliased = signed.to_vec();
    aliased[end - 3..end].copy_from_slice(b"new");
    let original = SignedIntentEnvelopeV1::try_from(signed)?;
    let changed = SignedIntentEnvelopeV1::try_from(aliased.as_slice())?;
    assert_eq!(changed.payload, original.payload);
    assert_eq!(changed.signature, original.signature);
    Ok(aliased)
}

#[test]
fn control_authority_alias_rejection() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = ControlStore::open(dir.path())?;
    let initial = trust();
    let mut owner = AuthorityLeaseOwner::new(store.clone(), initial.clone())?;
    let (old_request, unseen) = fixture(1, &initial.issuers[0], 1);
    let request_id = old_request.request_id;
    owner.request(old_request)?;
    let old_signed = signed(&unseen)?;
    let (advance, current) = fixture(2, &initial.issuers[0], 5000);
    let advance_id = advance.request_id;
    owner.request(advance)?;
    owner.accept([5; 16], advance_id, [8; 16], &signed(&current)?, 100)?;
    reject_unchanged(&store, AuthorityErrorCodeV1::Replay, || {
        owner.accept([5; 16], request_id, [8; 16], &old_signed, 100)
    })?;

    let mut removed = initial.clone();
    removed.revision = 2;
    removed.issuers[0].issuer_id = [30; 16];
    owner = AuthorityLeaseOwner::new(store.clone(), removed)?;
    reject_unchanged(&store, AuthorityErrorCodeV1::Denied, || {
        owner.accept([5; 16], request_id, [8; 16], &old_signed, 100)
    })?;
    let mut restored = initial;
    restored.revision = 3;
    restored.issuers[0].key_id = b"new".to_vec();
    owner = AuthorityLeaseOwner::new(store.clone(), restored.clone())?;
    let aliased = alias_key(&old_signed)?;
    reject_unchanged(&store, AuthorityErrorCodeV1::Denied, || {
        owner.accept([5; 16], request_id, [8; 16], &aliased, 100)
    })?;
    let retained = store.authority_state()?;
    drop(owner);
    drop(store);

    let store = ControlStore::open(dir.path())?;
    let owner = AuthorityLeaseOwner::new(store.clone(), restored)?;
    assert_eq!(store.authority_state()?, retained);
    reject_unchanged(&store, AuthorityErrorCodeV1::Denied, || {
        owner.accept([5; 16], request_id, [8; 16], &aliased, 100)
    })
}

#[test]
fn control_authority_window_capacity() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = ControlStore::open(dir.path())?;
    let mut trusted = trust();
    trusted.issuers = (1..=256)
        .map(|index| {
            let mut issuer = trusted.issuers[0].clone();
            issuer.issuer_id = id(index, 5);
            issuer
        })
        .collect();
    let owner = AuthorityLeaseOwner::new(store.clone(), trusted.clone())?;
    for (index, issuer) in (1..=256).zip(&trusted.issuers) {
        let (request, intent) = fixture(index, issuer, 1);
        let request_id = request.request_id;
        owner.request(request)?;
        owner.accept([5; 16], request_id, [8; 16], &signed(&intent)?, 100)?;
    }
    assert_eq!(store.authority_state()?.windows.len(), 256);
    drop(owner);
    drop(store);

    let store = ControlStore::open(dir.path())?;
    let owner = AuthorityLeaseOwner::new(store.clone(), trusted.clone())?;
    let (request, intent) = fixture(257, &trusted.issuers[0], 2);
    let request_id = request.request_id;
    owner.request(request)?;
    owner.accept([5; 16], request_id, [8; 16], &signed(&intent)?, 100)?;
    assert_eq!(store.authority_state()?.windows.len(), 256);

    trusted.revision = 2;
    trusted.issuers[0].sequence_epoch = 2;
    let owner = AuthorityLeaseOwner::new(store.clone(), trusted.clone())?;
    let (request, intent) = fixture(258, &trusted.issuers[0], 1);
    let request_id = request.request_id;
    owner.request(request)?;
    reject_unchanged(&store, AuthorityErrorCodeV1::Unavailable, || {
        owner.accept([5; 16], request_id, [8; 16], &signed(&intent)?, 100)
    })
}
