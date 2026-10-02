use axum::http::{HeaderMap, Uri, header};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    fn parse(value: &str) -> Result<Self, String> {
        let uri: Uri = value.parse().map_err(|_| "invalid dashboard origin")?;
        let scheme = uri
            .scheme_str()
            .ok_or("dashboard origin needs http:// or https://")?;
        let default_port = match scheme {
            "http" => 80,
            "https" => 443,
            _ => return Err("dashboard origin needs http:// or https://".into()),
        };
        let authority = uri.authority().ok_or("dashboard origin needs a host")?;
        if authority.as_str().contains('@')
            || uri.query().is_some()
            || !matches!(uri.path(), "" | "/")
            || value.contains('#')
        {
            return Err("dashboard origin must contain only scheme, host and port".into());
        }
        if authority.port().is_some() && authority.port_u16().is_none() {
            return Err("dashboard origin has an invalid port".into());
        }
        let host = authority.host().to_ascii_lowercase();
        if host.is_empty() {
            return Err("dashboard origin needs a host".into());
        }
        Ok(Self {
            scheme: scheme.into(),
            host,
            port: authority.port_u16().unwrap_or(default_port),
        })
    }
}

/// Browser origins and Host authorities come from configuration, never from
/// request headers. This also prevents DNS rebinding to a loopback listener.
#[derive(Debug, Clone)]
pub(crate) struct DashboardPolicy {
    origins: Vec<Origin>,
}

impl DashboardPolicy {
    pub(crate) fn new(bind: &str, port: u16, tls: bool, extra: &[String]) -> Result<Self, String> {
        let scheme = if tls { "https" } else { "http" };
        let mut hosts = vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "[::1]".to_owned(),
        ];
        if !matches!(bind, "0.0.0.0" | "::" | "[::]") {
            hosts.push(if bind.contains(':') && !bind.starts_with('[') {
                format!("[{bind}]")
            } else {
                bind.to_owned()
            });
        }
        let mut origins = hosts
            .iter()
            .map(|host| Origin::parse(&format!("{scheme}://{host}:{port}")))
            .collect::<Result<Vec<_>, _>>()?;
        for value in extra {
            origins.push(Origin::parse(value)?);
        }
        Ok(Self { origins })
    }

    pub(crate) fn allows(&self, headers: &HeaderMap, uri: &Uri) -> bool {
        if headers.get_all(header::HOST).iter().count() > 1
            || headers.get_all(header::ORIGIN).iter().count() > 1
        {
            return false;
        }
        let authority = match headers.get(header::HOST) {
            Some(value) => match value.to_str() {
                Ok(value) => value,
                Err(_) => return false,
            },
            None => match uri.authority() {
                Some(value) => value.as_str(),
                None => return false,
            },
        };
        if authority.parse::<axum::http::uri::Authority>().is_err() || authority.contains('@') {
            return false;
        }
        // Parse as a complete origin to reject userinfo, paths and bad ports.
        let host_allowed = self.origins.iter().any(|allowed| {
            Origin::parse(&format!("{}://{authority}", allowed.scheme))
                .is_ok_and(|request| request.host == allowed.host && request.port == allowed.port)
        });
        if !host_allowed {
            return false;
        }
        // Native clients deliberately may omit Origin; they still need an
        // allowed Host and any configured authentication credentials.
        match headers.get(header::ORIGIN) {
            None => true,
            Some(value) => value
                .to_str()
                .ok()
                .and_then(|value| Origin::parse(value).ok())
                .is_some_and(|origin| self.origins.contains(&origin)),
        }
    }
}

pub(crate) fn validate(bind: &str, port: u16, tls: bool, origins: &[String]) -> Result<(), String> {
    DashboardPolicy::new(bind, port, tls, origins).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_foreign_null_malformed_and_rebinding_requests() {
        let policy = DashboardPolicy::new("127.0.0.1", 8080, false, &[]).unwrap();
        let uri = "/ws".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:8080".parse().unwrap());
        assert!(policy.allows(&headers, &uri));
        for origin in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert!(policy.allows(&headers, &uri));
        }
        for origin in [
            "null",
            "https://localhost:8080",
            "http://unrelated.invalid",
            "http://localhost:8081",
            "http://localhost:8080/path",
            "http://localhost:8080#fragment",
        ] {
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert!(!policy.allows(&headers, &uri), "accepted {origin}");
        }
        headers.remove(header::ORIGIN);
        headers.insert(header::HOST, "attacker.invalid:8080".parse().unwrap());
        assert!(!policy.allows(&headers, &uri));
    }

    #[test]
    fn explicitly_configured_https_host_is_allowed() {
        let policy = DashboardPolicy::new(
            "0.0.0.0",
            8443,
            true,
            &["https://capture.example:8443".into()],
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "capture.example:8443".parse().unwrap());
        headers.insert(
            header::ORIGIN,
            "https://capture.example:8443".parse().unwrap(),
        );
        assert!(policy.allows(&headers, &"/ws".parse().unwrap()));
        assert!(DashboardPolicy::new("127.0.0.1", 8080, false, &["*".into()]).is_err());
    }
}
