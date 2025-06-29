use verdict::{ChromePolicy, RootStore, Task, Validator};

const ROOTS: &[u8] = include_bytes!("../tests/roots.pem");
const GOOGLE_CHAIN: &[u8] = include_bytes!("../tests/chains/google.pem");

fn main() {
    let roots = RootStore::from_pem(ROOTS).expect("failed to parse root certificates");
    let validator =
        Validator::from_roots(ChromePolicy::default(), &roots).expect("failed to create validator");

    eprintln!("loaded {} root certificates", validator.num_roots());

    let task = Task::new_server_auth(Some("google.com"), 1725029869);

    let valid = validator
        .validate_pem(GOOGLE_CHAIN, &task)
        .expect("failed to validate certificate chain");

    eprintln!(
        "certificate chain is {} for the domain {} at {}",
        if valid { "valid" } else { "invalid" },
        task.hostname().unwrap(),
        task.timestamp(),
    );
}
