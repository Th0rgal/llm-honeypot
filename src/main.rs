//! llm-honeypot — a tiny, dependency-free LLM endpoint honeypot.
//!
//! Impersonates an unauthenticated OpenAI-/Ollama-style inference server and
//! logs every request (IP, User-Agent, presented API key, model, full prompt)
//! as one JSON line. It never runs a model: chat replies are a fixed, harmless
//! string, so the endpoint produces nothing usable. Standard library only.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Config {
    addr: String,
    log: Option<String>,
    rate: u32,
    rate_window: Duration,
    max_conn: usize,
    max_body: usize,
    server_name: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let cfg = Config {
        addr: env_or("HONEYPOT_ADDR", "127.0.0.1:8099"),
        log: std::env::var("HONEYPOT_LOG").ok().filter(|s| !s.is_empty()),
        rate: env_or("HONEYPOT_RATE", "30").parse().unwrap_or(30),
        rate_window: Duration::from_secs(env_or("HONEYPOT_RATE_WINDOW_SECS", "10").parse().unwrap_or(10)),
        max_conn: env_or("HONEYPOT_MAX_CONN", "128").parse().unwrap_or(128),
        max_body: env_or("HONEYPOT_MAX_BODY", "4194304").parse().unwrap_or(4194304),
        server_name: env_or("HONEYPOT_SERVER_NAME", "uvicorn"),
    };
    let cfg = Arc::new(cfg);

    let listener = TcpListener::bind(&cfg.addr).unwrap_or_else(|e| {
        eprintln!("bind {} failed: {e}", cfg.addr);
        std::process::exit(1);
    });
    eprintln!("llm-honeypot listening on {}", cfg.addr);

    let live = Arc::new(AtomicUsize::new(0));
    let limiter: Arc<Mutex<HashMap<String, (Instant, u32)>>> = Arc::new(Mutex::new(HashMap::new()));
    let logfile = cfg.log.as_ref().map(|p| {
        Arc::new(Mutex::new(
            OpenOptions::new().create(true).append(true).open(p).expect("open log file"),
        ))
    });

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        if live.load(Ordering::Relaxed) >= cfg.max_conn {
            // Too many in flight: shed load without spawning.
            let _ = quick_503(&stream);
            if let Some(f) = &logfile {
                let ip = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
                if let Ok(mut f) = f.lock() {
                    let _ = writeln!(f, "{{\"ts\":{},\"event\":\"overflow\",\"peer\":{}}}", now_unix(), json_str(&ip));
                }
            }
            continue;
        }
        live.fetch_add(1, Ordering::Relaxed);
        let (cfg, live, limiter, logfile) =
            (cfg.clone(), live.clone(), limiter.clone(), logfile.clone());
        std::thread::spawn(move || {
            let _ = handle(stream, &cfg, &limiter, logfile.as_deref());
            live.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn quick_503(stream: &TcpStream) -> std::io::Result<()> {
    let mut s = stream.try_clone()?;
    s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

struct Request {
    method: String,
    path: String,
    version: String,
    headers: Vec<(String, String)>,
    body: String,
    truncated: bool,
}

fn header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn handle(
    stream: TcpStream,
    cfg: &Config,
    limiter: &Mutex<HashMap<String, (Instant, u32)>>,
    logfile: Option<&Mutex<std::fs::File>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let peer = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "?".into());
    let mut reader = BufReader::new(stream.try_clone()?);

    let req = match read_request(&mut reader, cfg.max_body) {
        Some(r) => r,
        None => return Ok(()),
    };

    // Real client IP from the reverse proxy; fall back to the socket peer.
    let ip = header(&req, "x-forwarded-for")
        .and_then(|v| v.split(',').next_back())
        .map(|s| s.trim().to_string())
        .or_else(|| header(&req, "x-real-ip").map(|s| s.trim().to_string()))
        .unwrap_or(peer);

    let model = find_json_str(&req.body, "model");
    let stream_flag = find_json_bool(&req.body, "stream").unwrap_or(false);
    let api_key = header(&req, "authorization")
        .map(|v| v.trim_start_matches("Bearer ").trim_start_matches("bearer ").to_string())
        .or_else(|| header(&req, "x-api-key").map(|s| s.to_string()));

    log_request(logfile, &ip, &req, &model, stream_flag, api_key.as_deref());

    if rate_limited(limiter, &ip, cfg.rate, cfg.rate_window) {
        return respond(&stream, cfg, 429, "application/json",
            br#"{"error":{"message":"rate limit exceeded","type":"rate_limit_error"}}"#);
    }

    let path = req.path.split('?').next().unwrap_or(&req.path);
    route(&stream, cfg, &req, path, model.as_deref(), stream_flag)
}

fn route(
    stream: &TcpStream,
    cfg: &Config,
    req: &Request,
    path: &str,
    model: Option<&str>,
    stream_flag: bool,
) -> std::io::Result<()> {
    match (req.method.as_str(), path) {
        ("GET", "/health") | ("GET", "/health/readiness") | ("GET", "/healthz") =>
            respond(stream, cfg, 200, "application/json", br#"{"status":"ok"}"#),
        // Ollama's fingerprint (what Shodan & co. match on) on its port / hostname.
        ("GET", "/") | ("HEAD", "/") if looks_like_ollama(req) =>
            respond(stream, cfg, 200, "text/plain; charset=utf-8", b"Ollama is running"),
        ("GET", "/api/version") =>
            respond(stream, cfg, 200, "application/json", br#"{"version":"0.12.6"}"#),
        ("GET", "/api/ps") =>
            respond(stream, cfg, 200, "application/json", br#"{"models":[]}"#),
        ("GET", "/") =>
            respond(stream, cfg, 200, "application/json",
                br#"{"status":"ok","message":"OpenAI-compatible inference server"}"#),
        ("GET", "/v1/models") | ("GET", "/models") | ("GET", "/api/models")
        | ("GET", "/v1/models/") =>
            respond(stream, cfg, 200, "application/json", MODELS_OPENAI.as_bytes()),
        ("GET", "/api/tags") =>
            respond(stream, cfg, 200, "application/json", MODELS_OLLAMA.as_bytes()),
        ("GET", "/v1/props") | ("GET", "/props") =>
            respond(stream, cfg, 200, "application/json", br#"{"default_generation_settings":{}}"#),
        // LiteLLM admin surface that proxy-hunters probe — plausible but empty.
        ("GET", "/key/list") | ("POST", "/key/list") =>
            respond(stream, cfg, 200, "application/json", br#"{"keys":[]}"#),
        ("GET", "/user/info") | ("POST", "/user/info") =>
            respond(stream, cfg, 200, "application/json", br#"{"user_id":null,"teams":[]}"#),
        ("GET", "/spend/logs") | ("POST", "/spend/logs") =>
            respond(stream, cfg, 200, "application/json", b"[]"),
        ("GET", "/global/config") | ("GET", "/model/info") =>
            respond(stream, cfg, 200, "application/json", br#"{"data":[]}"#),
        ("GET", "/metrics") =>
            respond(stream, cfg, 200, "text/plain", b"# no metrics\n"),
        ("POST", "/v1/chat/completions") | ("POST", "/chat/completions") => {
            let m = model.unwrap_or("gpt-4o");
            if stream_flag {
                respond_sse_chat(stream, cfg, m)
            } else {
                respond(stream, cfg, 200, "application/json", chat_json(m).as_bytes())
            }
        }
        ("POST", "/v1/completions") | ("POST", "/completions") =>
            respond(stream, cfg, 200, "application/json",
                completion_json(model.unwrap_or("gpt-3.5-turbo-instruct")).as_bytes()),
        ("POST", "/api/generate") | ("POST", "/api/chat") =>
            respond(stream, cfg, 200, "application/json", OLLAMA_REPLY.as_bytes()),
        ("OPTIONS", _) => respond(stream, cfg, 204, "text/plain", b""),
        _ => respond(stream, cfg, 404, "application/json",
            br#"{"error":{"message":"Not Found","type":"invalid_request_error"}}"#),
    }
}

fn looks_like_ollama(req: &Request) -> bool {
    header(req, "x-honeypot-local-port") == Some("11434")
        || header(req, "host").is_some_and(|h| h.starts_with("ollama."))
}

// ---- canned payloads --------------------------------------------------------

const REPLY: &str = "Hello! I'm doing well, thank you for asking. How can I help you today?";

const MODELS_OPENAI: &str = r#"{"object":"list","data":[
{"id":"gpt-4o","object":"model","owned_by":"openai"},
{"id":"gpt-4o-mini","object":"model","owned_by":"openai"},
{"id":"llama-3.3-70b-instruct","object":"model","owned_by":"meta"},
{"id":"qwen2.5-coder-32b-instruct","object":"model","owned_by":"qwen"},
{"id":"deepseek-r1","object":"model","owned_by":"deepseek"},
{"id":"mixtral-8x7b-instruct","object":"model","owned_by":"mistralai"}]}"#;

const MODELS_OLLAMA: &str = r#"{"models":[
{"name":"llama3.3:70b","model":"llama3.3:70b","size":42520413916},
{"name":"qwen2.5-coder:32b","model":"qwen2.5-coder:32b","size":19851349856},
{"name":"deepseek-r1:70b","model":"deepseek-r1:70b","size":42520413916}]}"#;

const OLLAMA_REPLY: &str =
    "{\"model\":\"llama3.3:70b\",\"response\":\"Hello! How can I help you today?\",\"done\":true}";

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn chat_json(model: &str) -> String {
    format!(
        "{{\"id\":\"chatcmpl-honeypot\",\"object\":\"chat.completion\",\"created\":{},\
\"model\":{},\"choices\":[{{\"index\":0,\"message\":{{\"role\":\"assistant\",\"content\":{}}},\
\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":9,\"completion_tokens\":16,\"total_tokens\":25}}}}",
        now_unix(), json_str(model), json_str(REPLY)
    )
}

fn completion_json(model: &str) -> String {
    format!(
        "{{\"id\":\"cmpl-honeypot\",\"object\":\"text_completion\",\"created\":{},\"model\":{},\
\"choices\":[{{\"index\":0,\"text\":{},\"finish_reason\":\"stop\"}}],\
\"usage\":{{\"prompt_tokens\":9,\"completion_tokens\":16,\"total_tokens\":25}}}}",
        now_unix(), json_str(model), json_str(REPLY)
    )
}

fn respond_sse_chat(stream: &TcpStream, cfg: &Config, model: &str) -> std::io::Result<()> {
    let mut s = stream.try_clone()?;
    let head = format!(
        "HTTP/1.1 200 OK\r\nServer: {}\r\nContent-Type: text/event-stream\r\n\
Cache-Control: no-cache\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        cfg.server_name
    );
    s.write_all(head.as_bytes())?;
    let created = now_unix();
    let role = format!(
        "data: {{\"id\":\"chatcmpl-honeypot\",\"object\":\"chat.completion.chunk\",\"created\":{created},\
\"model\":{},\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}}}}]}}\n\n",
        json_str(model)
    );
    s.write_all(role.as_bytes())?;
    for word in REPLY.split_inclusive(' ') {
        let chunk = format!(
            "data: {{\"id\":\"chatcmpl-honeypot\",\"object\":\"chat.completion.chunk\",\"created\":{created},\
\"model\":{},\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}}}}]}}\n\n",
            json_str(model), json_str(word)
        );
        s.write_all(chunk.as_bytes())?;
        let _ = s.flush();
    }
    let done = format!(
        "data: {{\"id\":\"chatcmpl-honeypot\",\"object\":\"chat.completion.chunk\",\"created\":{created},\
\"model\":{},\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\ndata: [DONE]\n\n",
        json_str(model)
    );
    s.write_all(done.as_bytes())
}

fn respond(stream: &TcpStream, cfg: &Config, code: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let mut s = stream.try_clone()?;
    let reason = match code {
        200 => "OK", 204 => "No Content", 404 => "Not Found",
        429 => "Too Many Requests", 503 => "Service Unavailable", _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nServer: {}\r\nContent-Type: {ctype}\r\n\
Content-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        cfg.server_name, body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)
}

// ---- request parsing --------------------------------------------------------

fn read_request(reader: &mut BufReader<TcpStream>, max_body: usize) -> Option<Request> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut it = line.trim_end().split_whitespace();
    let method = it.next()?.to_string();
    let path = it.next().unwrap_or("/").to_string();
    let version = it.next().unwrap_or("-").to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).ok()? == 0 {
            break;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            if headers.len() < 128 {
                headers.push((k, v));
            }
        }
    }

    let (body, truncated) = if content_length > 0 {
        let want = content_length.min(max_body);
        let mut buf = Vec::with_capacity(want);
        let _ = reader.by_ref().take(want as u64).read_to_end(&mut buf);
        let short = buf.len() < want;
        (String::from_utf8_lossy(&buf).into_owned(), content_length > max_body || short)
    } else {
        (String::new(), false)
    };

    Some(Request { method, path, version, headers, body, truncated })
}

// ---- tiny JSON field extraction (no parser, no deps) ------------------------

/// Extract the string value of a top-levelish `"key": "value"` pair.
fn find_json_str(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let mut i = s.find(&pat)? + pat.len();
    let b = s.as_bytes();
    while i < b.len() && b[i] != b':' {
        i += 1;
    }
    i += 1;
    while i < b.len() && (b[i] as char).is_whitespace() {
        i += 1;
    }
    if i >= b.len() || b[i] != b'"' {
        return None;
    }
    i += 1;
    let mut out = String::new();
    while i < b.len() {
        match b[i] {
            b'\\' if i + 1 < b.len() => {
                out.push(b[i + 1] as char);
                i += 2;
            }
            b'"' => break,
            c => {
                out.push(c as char);
                i += 1;
            }
        }
        if out.len() > 256 {
            break;
        }
    }
    Some(out)
}

fn find_json_bool(s: &str, key: &str) -> Option<bool> {
    let pat = format!("\"{key}\"");
    let rest = &s[s.find(&pat)? + pat.len()..];
    let rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ':');
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

// ---- logging ----------------------------------------------------------------

fn log_request(
    logfile: Option<&Mutex<std::fs::File>>,
    ip: &str,
    req: &Request,
    model: &Option<String>,
    stream_flag: bool,
    api_key: Option<&str>,
) {
    let ua = header(req, "user-agent").unwrap_or("-");
    let mut headers = String::from("[");
    for (i, (k, v)) in req.headers.iter().enumerate() {
        if i > 0 {
            headers.push(',');
        }
        headers.push_str(&format!("[{},{}]", json_str(k), json_str(v)));
    }
    headers.push(']');
    let line = format!(
        "{{\"ts\":{},\"ts_ms\":{},\"ip\":{},\"method\":{},\"path\":{},\"version\":{},\"ua\":{},\
\"api_key\":{},\"model\":{},\"stream\":{},\"body_truncated\":{},\"body_len\":{},\"headers\":{},\"body\":{}}}\n",
        now_unix(),
        now_millis(),
        json_str(ip),
        json_str(&req.method),
        json_str(&req.path),
        json_str(&req.version),
        json_str(ua),
        api_key.map(json_str).unwrap_or_else(|| "null".into()),
        model.as_deref().map(json_str).unwrap_or_else(|| "null".into()),
        stream_flag,
        req.truncated,
        req.body.len(),
        headers,
        json_str(&req.body),
    );
    match logfile {
        Some(f) => {
            if let Ok(mut f) = f.lock() {
                let _ = f.write_all(line.as_bytes());
            }
        }
        None => {
            print!("{line}");
        }
    }
}

/// Minimal JSON string encoder (quotes + escapes control chars).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---- rate limiting ----------------------------------------------------------

fn rate_limited(
    limiter: &Mutex<HashMap<String, (Instant, u32)>>,
    ip: &str,
    max: u32,
    window: Duration,
) -> bool {
    let mut map = match limiter.lock() {
        Ok(m) => m,
        Err(_) => return false,
    };
    if map.len() > 10_000 {
        map.clear(); // crude bound; a flood of unique IPs resets the table
    }
    let now = Instant::now();
    let entry = map.entry(ip.to_string()).or_insert((now, 0));
    if now.duration_since(entry.0) > window {
        *entry = (now, 0);
    }
    entry.1 += 1;
    entry.1 > max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_model_and_stream() {
        let b = r#"{"model":"gpt-4o","stream":true,"messages":[]}"#;
        assert_eq!(find_json_str(b, "model").as_deref(), Some("gpt-4o"));
        assert_eq!(find_json_bool(b, "stream"), Some(true));
    }

    #[test]
    fn json_str_escapes() {
        assert_eq!(json_str("a\"b\n"), "\"a\\\"b\\n\"");
    }

    #[test]
    fn missing_fields_are_none() {
        assert_eq!(find_json_str("{}", "model"), None);
        assert_eq!(find_json_bool("{}", "stream"), None);
    }
}
