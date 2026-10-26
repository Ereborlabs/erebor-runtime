use super::KubernetesWorkloadIdentityV1 as Identity;

#[test]
fn binding_identity_vectors() {
    let authority = Identity::authority_binding_id("pod-a", "worker");
    assert_eq!(authority, "8e842d3f-90e8-8ea8-bb82-277f93b28c81");
    assert_eq!(
        Identity::runtime_binding_id(&authority, &"a".repeat(64)),
        "529aa49d-2b5a-85ac-bad8-3fb4dd7c32f1"
    );
    assert_ne!(
        Identity::runtime_binding_id(&authority, &"a".repeat(64)),
        Identity::runtime_binding_id(&authority, &"b".repeat(64))
    );
}

#[test]
fn container_identity_grammar() {
    let long = "x".repeat(1024);
    for valid in ["a", "containerd:Az9-_.", long.as_str()] {
        assert!(Identity::valid_container_id(valid), "{valid:?}");
    }
    for invalid in ["", "a b", "a/b", "a\nb", "é"] {
        assert!(!Identity::valid_container_id(invalid), "{invalid:?}");
    }
}
