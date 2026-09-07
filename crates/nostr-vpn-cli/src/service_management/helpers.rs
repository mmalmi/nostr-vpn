#[cfg(any(target_os = "windows", test))]
fn windows_command_line_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    let mut backslashes = 0_usize;
    for ch in value.chars() {
        match ch {
            '\\' => backslashes = backslashes.saturating_add(1),
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2).saturating_add(1)));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                quoted.push(ch);
            }
        }
    }
    if backslashes > 0 {
        quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2)));
    }
    quoted.push('"');
    quoted
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(crate) fn parse_nonzero_pid(value: &str) -> Option<u32> {
    value.trim().parse::<u32>().ok().filter(|pid| *pid > 0)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn systemd_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
