use super::*;

#[test]
fn serials_compare_in_the_arithmetic_of_rfc_1982() {
    assert!(serial_ge(5, 5));
    assert!(serial_ge(6, 5));
    assert!(!serial_ge(5, 6));
    // Across the wrap: 1 comes after 4,294,967,295.
    assert!(serial_ge(1, u32::MAX));
    assert!(!serial_ge(u32::MAX, 1));
}
