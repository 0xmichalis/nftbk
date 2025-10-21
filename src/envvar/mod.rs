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

/// Determines whether colored output should be enabled based on environment variables and command line flag.
///
/// The precedence is:
/// 1. If NO_COLOR is set (any value), disable colors
/// 2. If FORCE_COLOR is set (any value), enable colors  
/// 3. Otherwise, use the provided command line flag value
///
/// This follows the NO_COLOR (https://no-color.org/) and FORCE_COLOR (https://force-color.org/) standards.
pub fn should_enable_color(cli_no_color: bool) -> bool {
    // NO_COLOR takes precedence - if set (any value), disable colors
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    // FORCE_COLOR takes precedence over CLI flag - if set (any value), enable colors
    if std::env::var("FORCE_COLOR").is_ok() {
        return true;
    }

    // Otherwise, use the CLI flag (inverted because CLI flag is --no-color)
    !cli_no_color
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

#[cfg(test)]
mod should_enable_color_tests {
    use super::should_enable_color;

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
    fn test_color_environment_variables() {
        // Test 1: NO_COLOR env var disables colors
        std::env::set_var("NO_COLOR", "1");
        let _g1 = EnvGuard::new(vec!["NO_COLOR"]);

        // Should disable colors regardless of CLI flag
        assert!(!should_enable_color(false));
        assert!(!should_enable_color(true));
        drop(_g1);

        // Test 2: FORCE_COLOR env var enables colors
        std::env::remove_var("NO_COLOR");
        std::env::set_var("FORCE_COLOR", "1");
        let _g2 = EnvGuard::new(vec!["NO_COLOR", "FORCE_COLOR"]);

        // Should enable colors regardless of CLI flag
        assert!(should_enable_color(false));
        assert!(should_enable_color(true));
        drop(_g2);

        // Test 3: NO_COLOR takes precedence over FORCE_COLOR
        std::env::set_var("NO_COLOR", "1");
        std::env::set_var("FORCE_COLOR", "1");
        let _g3 = EnvGuard::new(vec!["NO_COLOR", "FORCE_COLOR"]);

        // NO_COLOR should take precedence
        assert!(!should_enable_color(false));
        assert!(!should_enable_color(true));
        drop(_g3);

        // Test 4: Uses CLI flag when no env vars are set
        std::env::remove_var("NO_COLOR");
        std::env::remove_var("FORCE_COLOR");
        let _g4 = EnvGuard::new(vec!["NO_COLOR", "FORCE_COLOR"]);

        // Should use CLI flag (inverted because it's --no-color)
        assert!(should_enable_color(false)); // --no-color=false means enable colors
        assert!(!should_enable_color(true)); // --no-color=true means disable colors
        drop(_g4);

        // Test 5: Handles empty env var values
        std::env::set_var("NO_COLOR", "");
        let _g5 = EnvGuard::new(vec!["NO_COLOR"]);

        // Empty value should still disable colors (any value disables)
        assert!(!should_enable_color(false));
        assert!(!should_enable_color(true));
        drop(_g5);
    }
}
