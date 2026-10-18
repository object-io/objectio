//! AWS managed policies: the few that S3 and IAM clients attach by ARN
//! (`arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess`).
//!
//! They are built in, the same in every cluster, and read-only: nothing
//! stores them. An attachment names one as `aws:<name>` (a stored policy's
//! name can't contain `:`), and whoever evaluates it reads the document
//! from here.

/// How an attachment names an AWS managed policy: `aws:<name>`.
pub const PREFIX: &str = "aws:";

/// Every AWS managed policy, by name, with its document.
pub const POLICIES: &[(&str, &str)] = &[
    (
        "AmazonS3FullAccess",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","s3-object-lambda:*"],"Resource":"*"}]}"#,
    ),
    (
        "AmazonS3ReadOnlyAccess",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","s3:Describe*","s3-object-lambda:Get*","s3-object-lambda:List*"],"Resource":"*"}]}"#,
    ),
    (
        "IAMFullAccess",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*"],"Resource":"*"}]}"#,
    ),
    (
        "IAMReadOnlyAccess",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GenerateCredentialReport","iam:GenerateServiceLastAccessedDetails","iam:Get*","iam:List*","iam:SimulateCustomPolicy","iam:SimulatePrincipalPolicy"],"Resource":"*"}]}"#,
    ),
];

/// The document of the AWS managed policy `name`.
#[must_use]
pub fn document(name: &str) -> Option<&'static str> {
    POLICIES.iter().find(|(n, _)| *n == name).map(|(_, d)| *d)
}

/// The document of an attachment's policy name, if it names an AWS managed
/// policy (`aws:<name>`).
#[must_use]
pub fn attached(stored_name: &str) -> Option<&'static str> {
    document(stored_name.strip_prefix(PREFIX)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_document_parses_as_a_policy() {
        for (name, doc) in POLICIES {
            assert!(
                crate::BucketPolicy::from_json(doc).is_ok(),
                "{name} doesn't parse"
            );
        }
    }

    #[test]
    fn attachments_name_them_with_the_prefix() {
        assert!(attached("aws:AmazonS3FullAccess").is_some());
        assert!(attached("AmazonS3FullAccess").is_none());
        assert!(attached("aws:NoSuchPolicy").is_none());
    }
}
