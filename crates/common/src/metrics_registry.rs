//! Metrics from components that run inside another process's `/metrics`.
//!
//! The all-in-one binary runs the block gateway in the same process as the
//! S3 gateway, whose `/metrics` is the one scraped. A component registers a
//! renderer here and the gateway appends every registered one. Run on its
//! own, the component serves the same text on its own port.

use std::sync::RwLock;

type Renderer = Box<dyn Fn() -> String + Send + Sync>;

static RENDERERS: RwLock<Vec<(&'static str, Renderer)>> = RwLock::new(Vec::new());

/// Register `render` under `name`, replacing an earlier one of that name
/// (a component restarted in-process registers again).
pub fn register(name: &'static str, render: impl Fn() -> String + Send + Sync + 'static) {
    if let Ok(mut r) = RENDERERS.write() {
        r.retain(|(n, _)| *n != name);
        r.push((name, Box::new(render)));
    }
}

/// Everything registered, concatenated.
#[must_use]
pub fn render_registered() -> String {
    RENDERERS
        .read()
        .map(|r| r.iter().map(|(_, f)| f()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_renderer_registered_again_replaces_the_first() {
        register("test-component", || "a 1\n".to_string());
        register("test-component", || "a 2\n".to_string());
        let out = render_registered();
        assert!(out.contains("a 2"));
        assert!(!out.contains("a 1"));
    }
}
