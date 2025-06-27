pub fn is_defined(opt: &Option<String>) -> bool {
    opt.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
}
