use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=SSHC_VERSION");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");

    let version = env::var("SSHC_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(
            || match (env::var("GITHUB_REF_TYPE"), env::var("GITHUB_REF_NAME")) {
                (Ok(ref_type), Ok(ref_name))
                    if ref_type == "tag" && !ref_name.trim().is_empty() =>
                {
                    Some(ref_name)
                }
                _ => None,
            },
        )
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string()));

    println!("cargo:rustc-env=SSHC_BUILD_VERSION={version}");
}
