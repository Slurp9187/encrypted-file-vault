// tests/core_test.rs

mod common;

#[cfg(test)]
mod core; // This pulls in all the submodules declared in core/mod.rs

// Optional: add a simple smoke test
// #[test]
// fn core_suite_runs() {
//     // All tests in tests/core/*.rs will run automatically
//     assert!(true);
// }
