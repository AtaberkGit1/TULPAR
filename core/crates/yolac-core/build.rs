use std::process::Command;

/// Extracts a verified `owner/repo` slug ONLY from an explicit `YOLAC_GITHUB_REPO` env var
/// or the real `git remote get-url origin` if it points to `github.com`.
/// NEVER invents or fabricates a repository address.
fn parse_github_slug(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/').trim_end_matches(".git");
    let rest = if let Some(r) = trimmed.strip_prefix("https://github.com/") {
        r
    } else if let Some(r) = trimmed.strip_prefix("http://github.com/") {
        r
    } else if let Some(r) = trimmed.strip_prefix("git@github.com:") {
        r
    } else if !trimmed.contains("://") && trimmed.matches('/').count() == 1 {
        trimmed
    } else {
        return None;
    };

    let mut parts = rest.split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim();
    if parts.next().is_some() || owner.is_empty() || repo.is_empty() {
        return None;
    }
    let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    if owner.chars().all(valid_char) && repo.chars().all(valid_char) {
        Some(format!("{owner}/{repo}"))
    } else {
        None
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=YOLAC_GITHUB_REPO");
    println!("cargo:rerun-if-changed=../../../.git/config");

    let detected = std::env::var("YOLAC_GITHUB_REPO")
        .ok()
        .and_then(|v| parse_github_slug(&v))
        .or_else(|| {
            let out = Command::new("git")
                .args(["remote", "get-url", "origin"])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let url = String::from_utf8(out.stdout).ok()?;
            parse_github_slug(&url)
        });

    if let Some(slug) = detected {
        println!("cargo:rustc-env=YOLAC_DETECTED_GITHUB_REPO={slug}");
    }
}
