use std::env::VarError;

use anyhow::{Context, Result};

/// Source of environment variables. Production code passes [`ProcessEnv`];
/// tests pass a map, so they never modify the process environment.
pub trait Env: Sync {
    fn var(&self, name: &str) -> Result<String, VarError>;
}

/// Reads the process environment.
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Result<String, VarError> {
        std::env::var(name)
    }
}

#[cfg(test)]
impl Env for std::collections::HashMap<&str, &str> {
    fn var(&self, name: &str) -> Result<String, VarError> {
        self.get(name)
            .map(|value| value.to_string())
            .ok_or(VarError::NotPresent)
    }
}

pub fn is_defined(opt: &Option<String>) -> bool {
    opt.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
}

/// Resolves environment variable references in the form ${VAR_NAME} within the input string.
/// Returns an error if any referenced environment variable is not set.
pub fn resolve_env_placeholders(input: &str, env: &dyn Env) -> Result<String> {
    let re = regex::Regex::new(r"\$\{([A-Z0-9_]+)\}").unwrap();
    let mut resolved = input.to_string();
    for caps in re.captures_iter(input) {
        let var_name = &caps[1];
        let env_val = env
            .var(var_name)
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
pub fn should_enable_color(cli_no_color: bool, env: &dyn Env) -> bool {
    // NO_COLOR takes precedence - if set (any value), disable colors
    if env.var("NO_COLOR").is_ok() {
        return false;
    }

    // FORCE_COLOR takes precedence over CLI flag - if set (any value), enable colors
    if env.var("FORCE_COLOR").is_ok() {
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
    use std::collections::HashMap;

    use super::resolve_env_placeholders;

    #[test]
    fn replaces_single_variable() {
        let env = HashMap::from([("TEST_ENV_ONE", "abc")]);
        let out = resolve_env_placeholders("prefix-${TEST_ENV_ONE}-suffix", &env).unwrap();
        assert_eq!(out, "prefix-abc-suffix");
    }

    #[test]
    fn replaces_multiple_variables() {
        let env = HashMap::from([("TEST_ENV_A", "foo"), ("TEST_ENV_B", "bar")]);
        let out = resolve_env_placeholders("${TEST_ENV_A}:${TEST_ENV_B}", &env).unwrap();
        assert_eq!(out, "foo:bar");
    }

    #[test]
    fn no_placeholders_returns_input() {
        let input = "no placeholders here";
        let out = resolve_env_placeholders(input, &HashMap::new()).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn error_on_missing_variable() {
        let err = resolve_env_placeholders("value ${MISSING_VAR_X}", &HashMap::new()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("MISSING_VAR_X"));
        assert!(msg.contains("not set"));
    }
}

#[cfg(test)]
mod should_enable_color_tests {
    use std::collections::HashMap;

    use super::should_enable_color;

    #[test]
    fn test_color_environment_variables() {
        // Test 1: NO_COLOR env var disables colors
        let env = HashMap::from([("NO_COLOR", "1")]);

        // Should disable colors regardless of CLI flag
        assert!(!should_enable_color(false, &env));
        assert!(!should_enable_color(true, &env));

        // Test 2: FORCE_COLOR env var enables colors
        let env = HashMap::from([("FORCE_COLOR", "1")]);

        // Should enable colors regardless of CLI flag
        assert!(should_enable_color(false, &env));
        assert!(should_enable_color(true, &env));

        // Test 3: NO_COLOR takes precedence over FORCE_COLOR
        let env = HashMap::from([("NO_COLOR", "1"), ("FORCE_COLOR", "1")]);

        // NO_COLOR should take precedence
        assert!(!should_enable_color(false, &env));
        assert!(!should_enable_color(true, &env));

        // Test 4: Uses CLI flag when no env vars are set
        let env = HashMap::new();

        // Should use CLI flag (inverted because it's --no-color)
        assert!(should_enable_color(false, &env)); // --no-color=false means enable colors
        assert!(!should_enable_color(true, &env)); // --no-color=true means disable colors

        // Test 5: Handles empty env var values
        let env = HashMap::from([("NO_COLOR", "")]);

        // Empty value should still disable colors (any value disables)
        assert!(!should_enable_color(false, &env));
        assert!(!should_enable_color(true, &env));
    }
}
