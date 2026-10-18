//! The XML the query APIs answer with.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Text made safe for an element's content.
pub(crate) fn escape(s: &str) -> String {
    quick_xml::escape::escape(s).into_owned()
}

/// An element tree written as it is built.
#[derive(Default)]
pub(crate) struct Xml {
    body: String,
}

impl Xml {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `<tag>value</tag>`, the value escaped.
    pub(crate) fn el(&mut self, tag: &str, value: impl AsRef<str>) -> &mut Self {
        self.body.push('<');
        self.body.push_str(tag);
        self.body.push('>');
        self.body.push_str(&escape(value.as_ref()));
        self.body.push_str("</");
        self.body.push_str(tag);
        self.body.push('>');
        self
    }

    pub(crate) fn open(&mut self, tag: &str) -> &mut Self {
        self.body.push('<');
        self.body.push_str(tag);
        self.body.push('>');
        self
    }

    pub(crate) fn close(&mut self, tag: &str) -> &mut Self {
        self.body.push_str("</");
        self.body.push_str(tag);
        self.body.push('>');
        self
    }

    /// A policy document, URL-encoded as IAM sends them (SDKs decode it).
    pub(crate) fn document(&mut self, tag: &str, json: &str) -> &mut Self {
        self.el(tag, urlencoding::encode(json))
    }
}

/// `<{action}Response xmlns=…><{action}Result>{result}</…><ResponseMetadata>…`.
pub(crate) fn respond(action: &str, ns: &str, result: Option<Xml>) -> Response {
    let mut body =
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<{action}Response xmlns=\"{ns}\">");
    // An empty result too: SDKs expect one for every call whose answer has
    // a shape, empty or not (UpdateRole's), and ignore it for the others.
    let result = result.map(|r| r.body).unwrap_or_default();
    body.push_str(&format!("<{action}Result>{result}</{action}Result>"));
    body.push_str(&format!(
        "<ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{action}Response>",
        super::request_id()
    ));
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/xml")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_escaped_and_documents_encoded() {
        let mut x = Xml::new();
        x.open("User").el("UserName", "a<b&c").close("User");
        x.document("PolicyDocument", r#"{"a":"b c"}"#);
        assert_eq!(
            x.body,
            "<User><UserName>a&lt;b&amp;c</UserName></User>\
             <PolicyDocument>%7B%22a%22%3A%22b%20c%22%7D</PolicyDocument>"
        );
    }
}
