use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use url::Url;

const MAX_LSP_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ARGUMENTS: usize = 32;
const MAX_ARGUMENT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageServerKind {
    TypeScript,
    Pyright,
    RustAnalyzer,
}

impl LanguageServerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypeScript => "typescript",
            Self::Pyright => "pyright",
            Self::RustAnalyzer => "rust_analyzer",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::TypeScript => "TypeScript / JavaScript",
            Self::Pyright => "Python (Pyright)",
            Self::RustAnalyzer => "Rust Analyzer",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "typescript" => Some(Self::TypeScript),
            "pyright" => Some(Self::Pyright),
            "rust_analyzer" => Some(Self::RustAnalyzer),
            _ => None,
        }
    }

    pub fn supports_indexed_language(self, language: &str) -> bool {
        match self {
            Self::TypeScript => matches!(language, "TypeScript" | "TypeScript TSX" | "JavaScript"),
            Self::Pyright => language == "Python",
            Self::RustAnalyzer => language == "Rust",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LanguageServerConfig {
    pub kind: LanguageServerKind,
    pub executable_path: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub initialization_options: Option<Value>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LspPosition {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LspRange {
    pub start: LspPosition,
    pub end: LspPosition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LspLocation {
    pub uri: String,
    pub range: LspRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentSymbolView {
    pub name: String,
    pub kind: u32,
    pub range: LspRange,
    pub selection_range: LspRange,
    pub container_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServerCapabilities {
    pub document_symbol: bool,
    pub definition: bool,
    pub references: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServerInfo {
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Error)]
pub enum LspError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("language server executable must be an absolute path: {0}")]
    RelativeExecutable(String),
    #[error("language server executable does not resolve to a regular file: {0}")]
    InvalidExecutable(String),
    #[error("language server executable cannot be inside the analyzed project: {0}")]
    ExecutableInsideProject(String),
    #[error("Windows batch and PowerShell launchers are not allowed; configure an executable directly: {0}")]
    ScriptLauncherNotAllowed(String),
    #[error("language server arguments exceed the bounded command policy")]
    InvalidArguments,
    #[error("external language server execution requires explicit project trust")]
    TrustRequired,
    #[error("cannot represent path as a file URI: {0}")]
    InvalidFileUri(String),
    #[error("invalid LSP frame: {0}")]
    InvalidFrame(String),
    #[error("LSP message exceeded the {MAX_LSP_MESSAGE_BYTES} byte limit")]
    MessageTooLarge,
    #[error("language server channel closed")]
    ChannelClosed,
    #[error("language server request timed out: {0}")]
    Timeout(String),
    #[error("language server returned error {code}: {message}")]
    Remote { code: i64, message: String },
    #[error("invalid language server response: {0}")]
    InvalidResponse(String),
}

#[derive(Debug)]
struct ValidatedConfig {
    kind: LanguageServerKind,
    executable_path: PathBuf,
    arguments: Vec<String>,
    initialization_options: Option<Value>,
}

impl LanguageServerConfig {
    fn validate(&self, project_root: &Path) -> Result<ValidatedConfig, LspError> {
        let executable = PathBuf::from(&self.executable_path);
        if !executable.is_absolute() {
            return Err(LspError::RelativeExecutable(self.executable_path.clone()));
        }
        if self.arguments.len() > MAX_ARGUMENTS
            || self
                .arguments
                .iter()
                .any(|value| value.len() > MAX_ARGUMENT_BYTES || value.contains('\0'))
        {
            return Err(LspError::InvalidArguments);
        }
        #[cfg(windows)]
        if executable
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "cmd" | "bat" | "ps1"))
        {
            return Err(LspError::ScriptLauncherNotAllowed(
                self.executable_path.clone(),
            ));
        }

        let project_root = fs::canonicalize(project_root)?;
        let executable_path = fs::canonicalize(&executable)
            .map_err(|_| LspError::InvalidExecutable(self.executable_path.clone()))?;
        if !fs::metadata(&executable_path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
        {
            return Err(LspError::InvalidExecutable(self.executable_path.clone()));
        }
        if executable_path.starts_with(&project_root) {
            return Err(LspError::ExecutableInsideProject(
                executable_path.display().to_string(),
            ));
        }

        Ok(ValidatedConfig {
            kind: self.kind,
            executable_path,
            arguments: self.arguments.clone(),
            initialization_options: self.initialization_options.clone(),
        })
    }
}

pub struct StdioLanguageServer {
    child: Child,
    stdin: ChildStdin,
    receiver: Receiver<Result<Value, String>>,
    next_request_id: u64,
    request_timeout: Duration,
    root_uri: String,
    root_name: String,
    capabilities: ServerCapabilities,
    server_info: ServerInfo,
    closed: bool,
}

impl StdioLanguageServer {
    pub fn start(
        config: &LanguageServerConfig,
        project_root: &Path,
        trusted_project: bool,
        request_timeout: Duration,
    ) -> Result<Self, LspError> {
        if !trusted_project {
            return Err(LspError::TrustRequired);
        }
        let validated = config.validate(project_root)?;
        let canonical_root = fs::canonicalize(project_root)?;
        let root_uri = path_to_file_uri(&canonical_root)?;
        let root_name = canonical_root
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("workspace")
            .to_string();

        let mut command = Command::new(&validated.executable_path);
        command
            .args(&validated.arguments)
            .current_dir(&canonical_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| LspError::InvalidFrame("language server stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| LspError::InvalidFrame("language server stdout unavailable".into()))?;
        let (sender, receiver) = mpsc::channel();
        let _reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_lsp_message(&mut reader) {
                    Ok(Some(message)) => {
                        if sender.send(Ok(message)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });

        let mut client = Self {
            child,
            stdin,
            receiver,
            next_request_id: 1,
            request_timeout: request_timeout.max(Duration::from_millis(100)),
            root_uri,
            root_name,
            capabilities: ServerCapabilities::default(),
            server_info: ServerInfo::default(),
            closed: false,
        };
        client.initialize(validated.kind, validated.initialization_options)?;
        Ok(client)
    }

    pub fn capabilities(&self) -> &ServerCapabilities {
        &self.capabilities
    }

    pub fn server_info(&self) -> &ServerInfo {
        &self.server_info
    }

    pub fn open_document(
        &mut self,
        path: &Path,
        indexed_language: &str,
        text: &str,
    ) -> Result<String, LspError> {
        let uri = path_to_file_uri(path)?;
        let language_id = language_id_for_indexed_language(indexed_language, path)
            .ok_or_else(|| LspError::InvalidResponse(format!("unsupported indexed language: {indexed_language}")))?;
        self.notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": language_id,
                    "version": 1,
                    "text": text,
                }
            }),
        )?;
        Ok(uri)
    }

    pub fn close_document(&mut self, uri: &str) -> Result<(), LspError> {
        self.notify(
            "textDocument/didClose",
            json!({"textDocument": {"uri": uri}}),
        )
    }

    pub fn document_symbols(&mut self, uri: &str) -> Result<Vec<DocumentSymbolView>, LspError> {
        let result = self.request(
            "textDocument/documentSymbol",
            json!({"textDocument": {"uri": uri}}),
        )?;
        parse_document_symbols(&result)
    }

    pub fn definitions(
        &mut self,
        uri: &str,
        position: &LspPosition,
    ) -> Result<Vec<LspLocation>, LspError> {
        let result = self.request(
            "textDocument/definition",
            json!({"textDocument": {"uri": uri}, "position": position}),
        )?;
        parse_locations(&result)
    }

    pub fn references(
        &mut self,
        uri: &str,
        position: &LspPosition,
        include_declaration: bool,
    ) -> Result<Vec<LspLocation>, LspError> {
        let result = self.request(
            "textDocument/references",
            json!({
                "textDocument": {"uri": uri},
                "position": position,
                "context": {"includeDeclaration": include_declaration},
            }),
        )?;
        parse_locations(&result)
    }

    pub fn shutdown(&mut self) -> Result<(), LspError> {
        if self.closed {
            return Ok(());
        }
        let shutdown_result = self.request("shutdown", Value::Null);
        let exit_result = self.notify("exit", Value::Null);
        self.closed = true;
        let _ = self.child.kill();
        let _ = self.child.wait();
        shutdown_result?;
        exit_result
    }

    fn initialize(
        &mut self,
        kind: LanguageServerKind,
        initialization_options: Option<Value>,
    ) -> Result<(), LspError> {
        let mut params = json!({
            "processId": std::process::id(),
            "clientInfo": {"name": "CodeTwin ML", "version": env!("CARGO_PKG_VERSION")},
            "rootUri": self.root_uri,
            "workspaceFolders": [{"uri": self.root_uri, "name": self.root_name}],
            "capabilities": {
                "workspace": {"workspaceFolders": true, "configuration": true},
                "textDocument": {
                    "documentSymbol": {"hierarchicalDocumentSymbolSupport": true},
                    "definition": {"linkSupport": true},
                    "references": {},
                }
            },
            "trace": "off"
        });
        if let Some(options) = initialization_options {
            params["initializationOptions"] = options;
        } else if kind == LanguageServerKind::RustAnalyzer {
            params["initializationOptions"] = json!({
                "procMacro": {"enable": false},
                "cargo": {"buildScripts": {"enable": false}},
                "checkOnSave": false
            });
        }
        let response = self.request("initialize", params)?;
        let capabilities = response
            .get("capabilities")
            .ok_or_else(|| LspError::InvalidResponse("initialize response omitted capabilities".into()))?;
        self.capabilities = ServerCapabilities {
            document_symbol: provider_enabled(capabilities.get("documentSymbolProvider")),
            definition: provider_enabled(capabilities.get("definitionProvider")),
            references: provider_enabled(capabilities.get("referencesProvider")),
        };
        if let Some(info) = response.get("serverInfo") {
            self.server_info = ServerInfo {
                name: info.get("name").and_then(Value::as_str).map(str::to_string),
                version: info
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            };
        }
        self.notify("initialized", json!({}))
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, LspError> {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))?;

        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            if elapsed >= self.request_timeout {
                return Err(LspError::Timeout(method.to_string()));
            }
            let remaining = self.request_timeout - elapsed;
            let message = match self.receiver.recv_timeout(remaining) {
                Ok(Ok(message)) => message,
                Ok(Err(error)) => return Err(LspError::InvalidFrame(error)),
                Err(RecvTimeoutError::Timeout) => return Err(LspError::Timeout(method.to_string())),
                Err(RecvTimeoutError::Disconnected) => return Err(LspError::ChannelClosed),
            };

            if message.get("method").is_some() && message.get("id").is_some() {
                self.respond_to_server_request(&message)?;
                continue;
            }
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                let code = error.get("code").and_then(Value::as_i64).unwrap_or(-32_603);
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("language server request failed")
                    .to_string();
                return Err(LspError::Remote { code, message });
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), LspError> {
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": params}))
    }

    fn respond_to_server_request(&mut self, message: &Value) -> Result<(), LspError> {
        let Some(id) = message.get("id").cloned() else {
            return Ok(());
        };
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "workspace/configuration" => {
                let count = message
                    .pointer("/params/items")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                Value::Array((0..count).map(|_| Value::Null).collect())
            }
            "workspace/workspaceFolders" => {
                json!([{"uri": self.root_uri, "name": self.root_name}])
            }
            "client/registerCapability"
            | "client/unregisterCapability"
            | "window/workDoneProgress/create" => Value::Null,
            "workspace/applyEdit" => json!({
                "applied": false,
                "failureReason": "CodeTwin ML semantic enrichment is read-only"
            }),
            _ => {
                return self.send(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": "client method not supported"}
                }));
            }
        };
        self.send(json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    fn send(&mut self, message: Value) -> Result<(), LspError> {
        let body = serde_json::to_vec(&message)?;
        if body.len() > MAX_LSP_MESSAGE_BYTES {
            return Err(LspError::MessageTooLarge);
        }
        write!(self.stdin, "Content-Length: {}\r\n\r\n", body.len())?;
        self.stdin.write_all(&body)?;
        self.stdin.flush()?;
        Ok(())
    }
}

impl Drop for StdioLanguageServer {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.notify("exit", Value::Null);
            self.closed = true;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn language_id_for_indexed_language(language: &str, path: &Path) -> Option<&'static str> {
    match language {
        "TypeScript TSX" => Some("typescriptreact"),
        "TypeScript" => Some("typescript"),
        "JavaScript" => {
            if path.extension().and_then(|value| value.to_str()) == Some("jsx") {
                Some("javascriptreact")
            } else {
                Some("javascript")
            }
        }
        "Python" => Some("python"),
        "Rust" => Some("rust"),
        _ => None,
    }
}

pub fn path_to_file_uri(path: &Path) -> Result<String, LspError> {
    let canonical = fs::canonicalize(path)?;
    Url::from_file_path(&canonical)
        .map(|url| url.to_string())
        .map_err(|_| LspError::InvalidFileUri(canonical.display().to_string()))
}

pub fn file_uri_to_path(uri: &str) -> Option<PathBuf> {
    let url = Url::parse(uri).ok()?;
    if url.scheme() != "file" {
        return None;
    }
    url.to_file_path().ok()
}

fn provider_enabled(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::Object(_)) => true,
        _ => false,
    }
}

fn read_lsp_message(reader: &mut impl BufRead) -> Result<Option<Value>, LspError> {
    let mut content_length = None;
    let mut saw_header = false;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            return if saw_header {
                Err(LspError::InvalidFrame("unexpected EOF in LSP headers".into()))
            } else {
                Ok(None)
            };
        }
        saw_header = true;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                let length = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| LspError::InvalidFrame("invalid Content-Length".into()))?;
                if length > MAX_LSP_MESSAGE_BYTES {
                    return Err(LspError::MessageTooLarge);
                }
                content_length = Some(length);
            }
        }
    }
    let length = content_length
        .ok_or_else(|| LspError::InvalidFrame("missing Content-Length".into()))?;
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

fn parse_position(value: &Value) -> Result<LspPosition, LspError> {
    let line = value
        .get("line")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LspError::InvalidResponse("position.line is invalid".into()))?;
    let character = value
        .get("character")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LspError::InvalidResponse("position.character is invalid".into()))?;
    Ok(LspPosition { line, character })
}

fn parse_range(value: &Value) -> Result<LspRange, LspError> {
    Ok(LspRange {
        start: parse_position(
            value
                .get("start")
                .ok_or_else(|| LspError::InvalidResponse("range.start is missing".into()))?,
        )?,
        end: parse_position(
            value
                .get("end")
                .ok_or_else(|| LspError::InvalidResponse("range.end is missing".into()))?,
        )?,
    })
}

fn parse_location(value: &Value) -> Result<LspLocation, LspError> {
    if let Some(uri) = value.get("uri").and_then(Value::as_str) {
        let range = value
            .get("range")
            .ok_or_else(|| LspError::InvalidResponse("location.range is missing".into()))?;
        return Ok(LspLocation {
            uri: uri.to_string(),
            range: parse_range(range)?,
        });
    }
    if let Some(uri) = value.get("targetUri").and_then(Value::as_str) {
        let range = value
            .get("targetSelectionRange")
            .or_else(|| value.get("targetRange"))
            .ok_or_else(|| LspError::InvalidResponse("location link target range is missing".into()))?;
        return Ok(LspLocation {
            uri: uri.to_string(),
            range: parse_range(range)?,
        });
    }
    Err(LspError::InvalidResponse(
        "definition/reference item is not a Location or LocationLink".into(),
    ))
}

fn parse_locations(value: &Value) -> Result<Vec<LspLocation>, LspError> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(items) = value.as_array() {
        return items.iter().map(parse_location).collect();
    }
    Ok(vec![parse_location(value)?])
}

fn parse_document_symbols(value: &Value) -> Result<Vec<DocumentSymbolView>, LspError> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let items = value
        .as_array()
        .ok_or_else(|| LspError::InvalidResponse("documentSymbol result is not an array".into()))?;
    let mut symbols = Vec::new();
    for item in items {
        if item.get("location").is_some() {
            let location = item
                .get("location")
                .ok_or_else(|| LspError::InvalidResponse("symbol location missing".into()))?;
            let range = location
                .get("range")
                .ok_or_else(|| LspError::InvalidResponse("symbol location range missing".into()))?;
            symbols.push(DocumentSymbolView {
                name: required_string(item, "name")?,
                kind: required_u32(item, "kind")?,
                range: parse_range(range)?,
                selection_range: parse_range(range)?,
                container_name: item
                    .get("containerName")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
        } else {
            parse_document_symbol_tree(item, None, &mut symbols)?;
        }
    }
    Ok(symbols)
}

fn parse_document_symbol_tree(
    item: &Value,
    parent: Option<&str>,
    output: &mut Vec<DocumentSymbolView>,
) -> Result<(), LspError> {
    let name = required_string(item, "name")?;
    let range = parse_range(
        item.get("range")
            .ok_or_else(|| LspError::InvalidResponse("document symbol range missing".into()))?,
    )?;
    let selection_range = parse_range(
        item.get("selectionRange")
            .ok_or_else(|| LspError::InvalidResponse("document symbol selectionRange missing".into()))?,
    )?;
    let container_name = parent.map(str::to_string);
    output.push(DocumentSymbolView {
        name: name.clone(),
        kind: required_u32(item, "kind")?,
        range,
        selection_range,
        container_name,
    });
    let qualified = parent.map_or_else(|| name.clone(), |parent| format!("{parent}.{name}"));
    if let Some(children) = item.get("children").and_then(Value::as_array) {
        for child in children {
            parse_document_symbol_tree(child, Some(&qualified), output)?;
        }
    }
    Ok(())
}

fn required_string(value: &Value, key: &str) -> Result<String, LspError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| LspError::InvalidResponse(format!("{key} is missing or invalid")))
}

fn required_u32(value: &Value, key: &str) -> Result<u32, LspError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LspError::InvalidResponse(format!("{key} is missing or invalid")))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::{
        language_id_for_indexed_language, parse_document_symbols, parse_locations, read_lsp_message,
        LspPosition,
    };

    #[test]
    fn parses_content_length_framing() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":null}"#;
        let framed = format!("Content-Length: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n{}", body.len(), body);
        let mut cursor = Cursor::new(framed.into_bytes());
        let value = read_lsp_message(&mut cursor)
            .expect("frame")
            .expect("message");
        assert_eq!(value["id"], 1);
    }

    #[test]
    fn normalizes_location_and_location_link_results() {
        let value = json!([
            {
                "uri": "file:///work/a.ts",
                "range": {"start": {"line": 1, "character": 2}, "end": {"line": 1, "character": 5}}
            },
            {
                "targetUri": "file:///work/b.ts",
                "targetRange": {"start": {"line": 3, "character": 0}, "end": {"line": 3, "character": 4}},
                "targetSelectionRange": {"start": {"line": 3, "character": 1}, "end": {"line": 3, "character": 3}}
            }
        ]);
        let locations = parse_locations(&value).expect("locations");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[1].uri, "file:///work/b.ts");
        assert_eq!(locations[1].range.start, LspPosition { line: 3, character: 1 });
    }

    #[test]
    fn flattens_hierarchical_document_symbols_with_container_names() {
        let value = json!([{
            "name": "Service",
            "kind": 5,
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 4, "character": 1}},
            "selectionRange": {"start": {"line": 0, "character": 6}, "end": {"line": 0, "character": 13}},
            "children": [{
                "name": "run",
                "kind": 6,
                "range": {"start": {"line": 1, "character": 2}, "end": {"line": 3, "character": 3}},
                "selectionRange": {"start": {"line": 1, "character": 2}, "end": {"line": 1, "character": 5}}
            }]
        }]);
        let symbols = parse_document_symbols(&value).expect("symbols");
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[1].name, "run");
        assert_eq!(symbols[1].container_name.as_deref(), Some("Service"));
    }

    #[test]
    fn maps_indexed_languages_to_lsp_language_ids() {
        assert_eq!(
            language_id_for_indexed_language("TypeScript TSX", std::path::Path::new("view.tsx")),
            Some("typescriptreact")
        );
        assert_eq!(
            language_id_for_indexed_language("JavaScript", std::path::Path::new("view.jsx")),
            Some("javascriptreact")
        );
        assert_eq!(
            language_id_for_indexed_language("Python", std::path::Path::new("main.py")),
            Some("python")
        );
    }
}
