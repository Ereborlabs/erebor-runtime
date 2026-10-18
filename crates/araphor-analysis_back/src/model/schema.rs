#![cfg(test)]

use super::*;

#[test]
fn relation_names_stay_exact() -> Result<()> {
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let mut relations = BTreeMap::new();
    AdmittedModel::relation(&mut relations, "InputRows", &schema)?;
    let original = Arc::clone(&relations["InputRows"]);
    assert!(AdmittedModel::relation(&mut relations, "InputRows", &schema).is_err());
    AdmittedModel::relation(&mut relations, "INPUTROWS", &schema)?;
    assert!(Arc::ptr_eq(&relations["InputRows"], &original));
    Ok(())
}
