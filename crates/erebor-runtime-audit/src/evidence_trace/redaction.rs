#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvidenceRedactor;

impl EvidenceRedactor {
    pub(crate) fn redact(self, value: &str) -> String {
        let mut output = value.to_owned();
        for key in [
            "code",
            "state",
            "token",
            "access_token",
            "refresh_token",
            "client_secret",
        ] {
            output = self.redact_query_key(&output, key);
        }
        output
    }

    pub(crate) fn markdown_cell(self, value: &str) -> String {
        self.redact(value)
            .replace('|', "\\|")
            .replace(['\r', '\n'], " ")
            .trim()
            .to_owned()
    }

    pub(crate) fn truncate_markdown(self, value: &str, limit: usize) -> String {
        let text = self.markdown_cell(value);
        if text.len() <= limit {
            text
        } else {
            format!("{}...", &text[..limit.saturating_sub(3)])
        }
    }

    fn redact_query_key(self, value: &str, key: &str) -> String {
        let mut output = String::with_capacity(value.len());
        let mut rest = value;
        let query_key = format!("{key}=");
        while let Some(index) = rest.find(&query_key) {
            let (before, after_before) = rest.split_at(index);
            output.push_str(before);
            output.push_str(&query_key);
            output.push_str("redacted");
            let value_start = query_key.len();
            let after_value = after_before[value_start..]
                .find(['&', '#', ' ', ')'])
                .map_or(after_before.len(), |offset| value_start + offset);
            rest = &after_before[after_value..];
        }
        output.push_str(rest);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::EvidenceRedactor;

    #[test]
    fn redacts_sensitive_query_values() {
        let redacted = EvidenceRedactor
            .redact("http://127.0.0.1/callback?code=secret&state=secret&token=secret");

        assert!(redacted.contains("code=redacted"));
        assert!(redacted.contains("state=redacted"));
        assert!(redacted.contains("token=redacted"));
        assert!(!redacted.contains("secret"));
    }
}
