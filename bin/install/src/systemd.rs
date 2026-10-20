//! systemd units for a host's services.

use std::fmt::Write as _;

use crate::config::{Kind, Layout, Service};

/// The user meta and the gateway run as. OSDs run as root: they open raw
/// block devices.
pub const SERVICE_USER: &str = "objectio";

/// One argument as systemd's `ExecStart=` reads it: quoted when it holds
/// whitespace or quotes, with `%` (specifiers), `$` (variables) and `\`
/// escaped.
pub fn quote(arg: &str) -> String {
    let escaped = arg
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    if arg.is_empty()
        || arg
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'')
    {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

/// A command line as `ExecStart=` takes it.
pub fn exec_start(argv: &[String]) -> String {
    argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
}

/// The unit for `service`. `with_meta`: this host runs meta too, so the
/// others start after it.
pub fn unit(service: &Service, layout: &Layout, with_meta: bool) -> String {
    let mut u = String::new();
    let _ = writeln!(u, "[Unit]");
    let _ = writeln!(u, "Description={}", service.description);
    let _ = writeln!(u, "Documentation=https://object-io.github.io");
    let _ = writeln!(u, "After=network-online.target");
    let _ = writeln!(u, "Wants=network-online.target");
    if with_meta && service.kind != Kind::Meta {
        let _ = writeln!(u, "After=objectio-meta.service");
    }
    let _ = writeln!(u);
    let _ = writeln!(u, "[Service]");
    let _ = writeln!(u, "Type=simple");
    match service.kind {
        Kind::Osd => {
            let _ = writeln!(u, "User=root");
            let _ = writeln!(u, "Group=root");
        }
        Kind::Meta | Kind::Gateway => {
            let _ = writeln!(u, "User={SERVICE_USER}");
            let _ = writeln!(u, "Group={SERVICE_USER}");
        }
    }
    if service.kind == Kind::Gateway {
        // OBJECTIO_MASTER_KEY (SSE) and other settings read from the
        // environment; the file is optional.
        let _ = writeln!(u, "EnvironmentFile=-{}", layout.gateway_env().display());
    }
    let _ = writeln!(u, "ExecStart={}", exec_start(&service.argv));
    let _ = writeln!(u, "Restart=on-failure");
    let _ = writeln!(u, "RestartSec=5s");
    // Every acknowledged write is on disk already; this is time to finish
    // the calls in flight.
    let _ = writeln!(u, "TimeoutStopSec=60");
    match service.kind {
        Kind::Osd => {
            let _ = writeln!(u, "LimitNOFILE=1048576");
            let _ = writeln!(u, "LimitMEMLOCK=infinity");
            let _ = writeln!(u, "NoNewPrivileges=yes");
            let _ = writeln!(u, "ProtectHome=yes");
            let _ = writeln!(u, "PrivateTmp=yes");
        }
        Kind::Meta | Kind::Gateway => {
            let _ = writeln!(u, "LimitNOFILE=65536");
            let _ = writeln!(u, "NoNewPrivileges=yes");
            let _ = writeln!(u, "ProtectSystem=strict");
            let _ = writeln!(u, "ProtectHome=yes");
            let _ = writeln!(u, "PrivateTmp=yes");
            if service.kind == Kind::Meta {
                let _ = writeln!(u, "ReadWritePaths={}", layout.meta_data_dir().display());
            }
        }
    }
    let _ = writeln!(u, "SyslogIdentifier={}", service.unit);
    let _ = writeln!(u);
    let _ = writeln!(u, "[Install]");
    let _ = writeln!(u, "WantedBy=multi-user.target");
    u
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn service(kind: Kind, argv: &[&str]) -> Service {
        Service {
            unit: "objectio-x".into(),
            kind,
            description: "x".into(),
            argv: argv.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn arguments_are_quoted_as_systemd_reads_them() {
        assert_eq!(
            quote("/usr/local/bin/objectio-meta"),
            "/usr/local/bin/objectio-meta"
        );
        assert_eq!(quote("a b"), "\"a b\"");
        assert_eq!(quote("50%"), "50%%");
        assert_eq!(quote("$HOME"), "$$HOME");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn units_carry_the_command_line_and_run_as_the_service_user() {
        let layout = Layout::new(Path::new("/")).unwrap();
        let meta = unit(
            &service(
                Kind::Meta,
                &["/usr/local/bin/objectio-meta", "--node-id", "1"],
            ),
            &layout,
            true,
        );
        assert!(meta.contains("\nExecStart=/usr/local/bin/objectio-meta --node-id 1\n"));
        assert!(meta.contains("\nUser=objectio\n"));
        assert!(meta.contains("\nReadWritePaths=/var/lib/objectio/meta\n"));
        assert!(!meta.contains("After=objectio-meta.service"));
        // A HUP would stop a service that doesn't handle it.
        assert!(!meta.contains("ExecReload"));

        let gw = unit(&service(Kind::Gateway, &["/g"]), &layout, true);
        assert!(gw.contains("\nAfter=objectio-meta.service\n"));
        assert!(gw.contains("\nEnvironmentFile=-/etc/objectio/gateway.env\n"));
        let gw = unit(&service(Kind::Gateway, &["/g"]), &layout, false);
        assert!(!gw.contains("objectio-meta.service"));

        let osd = unit(&service(Kind::Osd, &["/o"]), &layout, false);
        assert!(osd.contains("\nUser=root\n"));
        assert!(!osd.contains("ProtectSystem"));
    }
}
