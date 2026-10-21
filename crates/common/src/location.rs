//! Storage locations (`s3://bucket/prefix`) and what lies under them.
//!
//! The data lake catalogs vend credentials scoped to a table's location,
//! so a location must stay inside the storage its catalog owns.

/// Whether `location` is `root` itself or a path under it. `.` and `..`
/// segments are refused: they would let a path that starts under `root`
/// leave it. An empty `root` contains nothing.
#[must_use]
pub fn within(location: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    if root.is_empty() || location.split('/').any(|seg| seg == ".." || seg == ".") {
        return false;
    }
    let location = location.trim_end_matches('/');
    location == root
        || location
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_location_is_its_root_or_under_it() {
        let root = "s3://iceberg-wh";
        assert!(within("s3://iceberg-wh", root));
        assert!(within("s3://iceberg-wh/", root));
        assert!(within("s3://iceberg-wh/db/t", root));
        assert!(within("s3://iceberg-wh/db/t/", "s3://iceberg-wh/"));
        // Another bucket, including one whose name starts the same.
        assert!(!within("s3://other/db/t", root));
        assert!(!within("s3://iceberg-wh2/db/t", root));
        assert!(!within("s3://iceberg-wh-other/t", root));
        // Climbing out.
        assert!(!within("s3://iceberg-wh/../other/t", root));
        assert!(!within("s3://iceberg-wh/db/./t", root));
        // No root, no location.
        assert!(!within("s3://iceberg-wh/db", ""));
        assert!(!within("", root));
    }
}
