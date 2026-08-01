//! Regression: <one-line description of the bug>
//!
//! Reported:  <date, or "found during PR-NN">
//! Symptom:   <what the user would have observed>
//! Cause:     <the actual mechanism, once understood>
//! Fixed in:  <PR / commit>
//!
//! # Why this could not be caught by an existing test
//!
//! <If an existing test should have caught it, that test is also wrong and
//! should be strengthened in the same change. Say which one and what changed.>

#[test]
fn describe_the_property_that_was_violated() {
    // Arrange: the smallest fixture that reproduces the bug.

    // Act: the operation that misbehaved.

    // Assert: the property that must hold. State it as the guarantee, not as
    // "the bug does not happen" — the guarantee is what future readers need.
    todo!("replace with a real reproduction");
}
