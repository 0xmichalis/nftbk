use anyhow::{Context, Result};

pub fn is_defined(opt: &Option<String>) -> bool {
    opt.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
}

/// Resolves environment variable references in the form ${VAR_NAME} within the input string.
/// Returns an error if any referenced environment variable is not set.
pub fn resolve_env_placeholders(input: &str) -> Result<String> {
    let re = regex::Regex::new(r"\$\{([A-Z0-9_]+)\}").unwrap();
    let mut resolved = input.to_string();
    for caps in re.captures_iter(input) {
        let var_name = &caps[1];
        let env_val = std::env::var(var_name)
            .with_context(|| format!("Environment variable '{var_name}' is not set"))?;
        resolved = resolved.replace(&format!("${{{var_name}}}"), &env_val);
    }
    Ok(resolved)
}

#[cfg(test)]
mod is_defined_tests {
    use super::is_defined;

    #[test]
    fn returns_true_for_non_empty_some() {
        let v = Some("val".to_string());
        assert!(is_defined(&v));
    }

    #[test]
    fn returns_false_for_empty_some() {
        let v = Some(String::new());
        assert!(!is_defined(&v));
    }

    #[test]
    fn returns_false_for_none() {
        let v: Option<String> = None;
        assert!(!is_defined(&v));
    }
}

#[cfg(test)]
mod resolve_env_placeholders_tests {
    use super::resolve_env_placeholders;

    struct EnvGuard {
        keys: Vec<&'static str>,
    }

    impl EnvGuard {
        fn new(keys: Vec<&'static str>) -> Self {
            Self { keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for k in &self.keys {
                std::env::remove_var(k);
            }
        }
    }

    #[test]
    fn replaces_single_variable() {
        std::env::set_var("TEST_ENV_ONE", "abc");
        let _g = EnvGuard::new(vec!["TEST_ENV_ONE"]);
        let out = resolve_env_placeholders("prefix-${TEST_ENV_ONE}-suffix").unwrap();
        assert_eq!(out, "prefix-abc-suffix");
    }

    #[test]
    fn replaces_multiple_variables() {
        std::env::set_var("TEST_ENV_A", "foo");
        std::env::set_var("TEST_ENV_B", "bar");
        let _g = EnvGuard::new(vec!["TEST_ENV_A", "TEST_ENV_B"]);
        let out = resolve_env_placeholders("${TEST_ENV_A}:${TEST_ENV_B}").unwrap();
        assert_eq!(out, "foo:bar");
    }

    #[test]
    fn no_placeholders_returns_input() {
        let input = "no placeholders here";
        let out = resolve_env_placeholders(input).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn error_on_missing_variable() {
        std::env::remove_var("MISSING_VAR_X");
        let err = resolve_env_placeholders("value ${MISSING_VAR_X}").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("MISSING_VAR_X"));
        assert!(msg.contains("not set"));
    }
}
