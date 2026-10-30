//! Chat-completions response parsing, for both whole JSON bodies and
//! Server-Sent Event streams. `reasoning_content` is counted and discarded:
//! CodeTwin surfaces only visible answers and operator-facing summaries.
use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::ProviderError;
use crate::types::{ChatResponse, ProposedToolCall, StreamDelta, ToolSpec, Usage};

pub const MAX_TOOL_CALLS: usize = 64;
const MAX_CONTENT_BYTES: usize = 512 * 1024;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

fn usage_from(value: &Value) -> Option<Usage> {
    let u = value.get("usage")?;
    if u.is_null() {
        return None;
    }
    Some(Usage {
        prompt_tokens: u.get("prompt_tokens")?.as_u64()?,
        completion_tokens: u.get("completion_tokens")?.as_u64()?,
        total_tokens: u.get("total_tokens")?.as_u64()?,
    })
}

/// Validate raw tool calls against the declared tool names. Unknown tools,
/// non-object arguments, oversized arguments and too many calls are rejected.
pub fn validate_tool_calls(
    raw: Vec<(String, String, String)>,
    declared: &[ToolSpec],
) -> Result<Vec<ProposedToolCall>, ProviderError> {
    if raw.len() > MAX_TOOL_CALLS {
        return Err(ProviderError::Protocol(format!(
            "{} tool calls exceed the documented limit of {MAX_TOOL_CALLS}",
            raw.len()
        )));
    }
    raw.into_iter()
        .map(|(id, name, args)| {
            if !declared.iter().any(|t| t.name == name) {
                return Err(ProviderError::Protocol(format!(
                    "model proposed undeclared tool `{}`",
                    name.chars().take(64).collect::<String>()
                )));
            }
            if args.len() > MAX_ARGUMENT_BYTES {
                return Err(ProviderError::Protocol("tool arguments too large".into()));
            }
            let arguments: Value =
                serde_json::from_str(if args.trim().is_empty() { "{}" } else { &args }).map_err(
                    |_| {
                        ProviderError::Protocol(format!(
                            "tool `{name}` arguments are not valid JSON"
                        ))
                    },
                )?;
            if !arguments.is_object() {
                return Err(ProviderError::Protocol(format!(
                    "tool `{name}` arguments must be an object"
                )));
            }
            if id.is_empty() || id.len() > 128 {
                return Err(ProviderError::Protocol(
                    "tool call id missing or too long".into(),
                ));
            }
            Ok(ProposedToolCall {
                id,
                name,
                arguments,
            })
        })
        .collect()
}

fn finish(
    request_id: &str,
    model: String,
    provider_id: Option<String>,
    content: Option<String>,
    raw_calls: Vec<(String, String, String)>,
    finish_reason: Option<String>,
    usage: Option<Usage>,
    reasoning: usize,
    streamed: bool,
    declared: &[ToolSpec],
) -> Result<ChatResponse, ProviderError> {
    let tool_calls = match validate_tool_calls(raw_calls, declared) {
        Ok(calls) => calls,
        // Arguments cut off mid-JSON by the output limit are truncation,
        // not a malformed call.
        Err(_) if finish_reason.as_deref() == Some("length") => {
            return Err(ProviderError::OutputBudgetExhausted)
        }
        Err(e) => return Err(e),
    };
    let content = content.filter(|c| !c.is_empty());
    if content.is_none() && tool_calls.is_empty() {
        return Err(match finish_reason.as_deref() {
            Some("length") => ProviderError::OutputBudgetExhausted,
            Some(other) => {
                ProviderError::Incomplete(format!("no visible answer (finish_reason `{other}`)"))
            }
            None => ProviderError::Incomplete("no visible answer".into()),
        });
    }
    Ok(ChatResponse {
        provider_id,
        request_id: request_id.to_owned(),
        model,
        content,
        tool_calls,
        finish_reason,
        usage,
        credits: 1,
        reasoning_chars_discarded: reasoning,
        streamed,
    })
}

/// Parse a non-streamed `chat.completion` body.
pub fn parse_completion(
    body: &[u8],
    request_id: &str,
    requested_model: &str,
    declared: &[ToolSpec],
) -> Result<ChatResponse, ProviderError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| ProviderError::Protocol("response is not valid JSON".into()))?;
    let choice = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .ok_or_else(|| ProviderError::Protocol("response has no choices".into()))?;
    let message = choice
        .get("message")
        .ok_or_else(|| ProviderError::Protocol("choice has no message".into()))?;
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if content
        .as_ref()
        .is_some_and(|c| c.len() > MAX_CONTENT_BYTES)
    {
        return Err(ProviderError::Protocol("response content too large".into()));
    }
    let reasoning = message
        .get("reasoning_content")
        .and_then(Value::as_str)
        .map_or(0, |r| r.chars().count());
    let mut raw = Vec::new();
    if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
        for call in calls {
            let f = call.get("function").unwrap_or(&Value::Null);
            raw.push((
                call.get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                f.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                match f.get("arguments") {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => String::new(),
                },
            ));
        }
    }
    finish(
        request_id,
        value
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(requested_model)
            .to_owned(),
        value.get("id").and_then(Value::as_str).map(str::to_owned),
        content,
        raw,
        choice
            .get("finish_reason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        usage_from(&value),
        reasoning,
        false,
        declared,
    )
}

#[derive(Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
    announced: bool,
}

/// Incremental SSE accumulator. Feed each line; call [`SseAccumulator::finish`]
/// once the stream ends. A stream without `data: [DONE]` is incomplete.
#[derive(Default)]
pub struct SseAccumulator {
    content: String,
    calls: BTreeMap<usize, PartialCall>,
    finish_reason: Option<String>,
    usage: Option<Usage>,
    model: Option<String>,
    provider_id: Option<String>,
    reasoning: usize,
    done: bool,
    malformed: usize,
}

impl SseAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Process one line; returns visible deltas for live display.
    pub fn feed(&mut self, line: &str) -> Result<Vec<StreamDelta>, ProviderError> {
        let line = line.trim_end_matches(['\r', '\n']);
        let Some(data) = line.strip_prefix("data:") else {
            return Ok(Vec::new()); // comments, `event:`, blank separators
        };
        let data = data.trim_start();
        if data == "[DONE]" {
            self.done = true;
            return Ok(Vec::new());
        }
        if self.done {
            return Err(ProviderError::Protocol("data after [DONE]".into()));
        }
        let chunk: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => {
                self.malformed += 1;
                if self.malformed > 3 {
                    return Err(ProviderError::Protocol(
                        "repeated malformed stream chunks".into(),
                    ));
                }
                return Ok(Vec::new());
            }
        };
        if let Some(err) = chunk.get("error") {
            let message = crate::error::error_message(err.to_string().as_bytes());
            return Err(ProviderError::Protocol(format!("stream error: {message}")));
        }
        if self.model.is_none() {
            self.model = chunk
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        if self.provider_id.is_none() {
            self.provider_id = chunk.get("id").and_then(Value::as_str).map(str::to_owned);
        }
        if let Some(usage) = usage_from(&chunk) {
            self.usage = Some(usage);
        }
        let mut out = Vec::new();
        let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
            return Ok(out);
        };
        for choice in choices {
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(reason.to_owned());
            }
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            if let Some(r) = delta.get("reasoning_content").and_then(Value::as_str) {
                self.reasoning += r.chars().count();
            }
            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                if self.content.len() + text.len() > MAX_CONTENT_BYTES {
                    return Err(ProviderError::Protocol("streamed content too large".into()));
                }
                self.content.push_str(text);
                if !text.is_empty() {
                    out.push(StreamDelta::Content(text.to_owned()));
                }
            }
            if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for call in calls {
                    let index = call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                    if index >= MAX_TOOL_CALLS {
                        return Err(ProviderError::Protocol(
                            "tool call index out of range".into(),
                        ));
                    }
                    let partial = self.calls.entry(index).or_default();
                    if let Some(id) = call.get("id").and_then(Value::as_str) {
                        partial.id = id.to_owned();
                    }
                    if let Some(f) = call.get("function") {
                        if let Some(name) = f.get("name").and_then(Value::as_str) {
                            partial.name.push_str(name);
                        }
                        if let Some(args) = f.get("arguments").and_then(Value::as_str) {
                            if partial.arguments.len() + args.len() > MAX_ARGUMENT_BYTES {
                                return Err(ProviderError::Protocol(
                                    "tool arguments too large".into(),
                                ));
                            }
                            partial.arguments.push_str(args);
                        }
                    }
                    if !partial.announced && !partial.name.is_empty() {
                        partial.announced = true;
                        out.push(StreamDelta::ToolCallStarted {
                            index,
                            name: partial.name.clone(),
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn finish(
        self,
        request_id: &str,
        requested_model: &str,
        declared: &[ToolSpec],
    ) -> Result<ChatResponse, ProviderError> {
        if !self.done {
            return Err(ProviderError::Incomplete(
                "stream ended before [DONE]; treat the response as incomplete".into(),
            ));
        }
        let raw = self
            .calls
            .into_values()
            .map(|c| (c.id, c.name, c.arguments))
            .collect();
        finish(
            request_id,
            self.model.unwrap_or_else(|| requested_model.to_owned()),
            self.provider_id,
            Some(self.content),
            raw,
            self.finish_reason,
            self.usage,
            self.reasoning,
            true,
            declared,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool() -> Vec<ToolSpec> {
        vec![ToolSpec {
            name: "get_time".into(),
            description: "t".into(),
            parameters: json!({"type":"object"}),
        }]
    }

    #[test]
    fn parses_live_shaped_tool_call_and_discards_reasoning() {
        // Shape captured from api.openmindai.org (2026-10-28), ids replaced.
        let body = br#"{"id":"chatcmpl-x","object":"chat.completion","model":"openmindai-lite","choices":[{"index":0,"message":{"content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"get_time","arguments":"{\"timezone\":\"UTC\"}"}}],"role":"assistant","reasoning_content":"hidden"},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":274,"completion_tokens":164,"total_tokens":438}}"#;
        let r = parse_completion(body, "req", "openmindai-lite", &tool()).unwrap();
        assert_eq!(r.tool_calls[0].arguments, json!({"timezone":"UTC"}));
        assert_eq!(r.reasoning_chars_discarded, 6);
        assert_eq!(r.usage.as_ref().unwrap().total_tokens, 438);
        assert!(!serde_json::to_string(&r).unwrap().contains("hidden"));
    }

    #[test]
    fn tool_arguments_cut_off_by_the_output_limit_are_budget_exhaustion() {
        let tools = [ToolSpec {
            name: "submit_plan".into(),
            description: String::new(),
            parameters: serde_json::json!({"type": "object"}),
        }];
        let body = br#"{"choices":[{"message":{"tool_calls":[{"id":"c","type":"function","function":{"name":"submit_plan","arguments":"{\"tasks\": [{\"key\""}}]},"finish_reason":"length"}]}"#;
        assert!(matches!(
            parse_completion(body, "r", "m", &tools),
            Err(ProviderError::OutputBudgetExhausted)
        ));
        let malformed = br#"{"choices":[{"message":{"tool_calls":[{"id":"c","type":"function","function":{"name":"submit_plan","arguments":"{oops"}}]},"finish_reason":"tool_calls"}]}"#;
        assert!(matches!(
            parse_completion(malformed, "r", "m", &tools),
            Err(ProviderError::Protocol(_))
        ));
    }

    #[test]
    fn truncated_reasoning_only_answer_is_incomplete() {
        let body = br#"{"choices":[{"message":{"content":null,"reasoning_content":"thinking"},"finish_reason":"length"}]}"#;
        assert!(matches!(
            parse_completion(body, "r", "m", &[]),
            Err(ProviderError::OutputBudgetExhausted)
        ));
    }

    #[test]
    fn rejects_undeclared_and_malformed_tool_calls() {
        let undeclared = br#"{"choices":[{"message":{"tool_calls":[{"id":"c","type":"function","function":{"name":"shell","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#;
        assert!(parse_completion(undeclared, "r", "m", &tool()).is_err());
        let bad_json = br#"{"choices":[{"message":{"tool_calls":[{"id":"c","type":"function","function":{"name":"get_time","arguments":"{oops"}}]},"finish_reason":"tool_calls"}]}"#;
        assert!(parse_completion(bad_json, "r", "m", &tool()).is_err());
        let array = br#"{"choices":[{"message":{"tool_calls":[{"id":"c","type":"function","function":{"name":"get_time","arguments":"[1]"}}]},"finish_reason":"tool_calls"}]}"#;
        assert!(parse_completion(array, "r", "m", &tool()).is_err());
        assert!(parse_completion(b"not json", "r", "m", &tool()).is_err());
    }

    #[test]
    fn accumulates_stream_with_tool_call_deltas() {
        let mut acc = SseAccumulator::new();
        let lines = [
            r#"data: {"id":"c1","model":"openmindai-lite","choices":[{"delta":{"role":"assistant","reasoning_content":"Here"}}]}"#,
            "",
            r#"data: {"choices":[{"delta":{"content":"p"}}]}"#,
            r#"data: {"choices":[{"delta":{"content":"ong"}}]}"#,
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-1","function":{"name":"get_time","arguments":"{\"time"}}]}}]}"#,
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"zone\":\"UTC\"}"}}]}}]}"#,
            r#"data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":null}"#,
            "data: [DONE]",
        ];
        let mut visible = Vec::new();
        for line in lines {
            visible.extend(acc.feed(line).unwrap());
        }
        assert!(visible.contains(&StreamDelta::Content("p".into())));
        let r = acc.finish("req", "openmindai-lite", &tool()).unwrap();
        assert_eq!(r.content.as_deref(), Some("pong"));
        assert_eq!(r.tool_calls[0].arguments, json!({"timezone":"UTC"}));
        assert_eq!(r.usage, None, "streams carry no reliable usage");
        assert!(r.streamed);
        assert_eq!(r.reasoning_chars_discarded, 4);
    }

    #[test]
    fn interrupted_or_corrupt_streams_fail() {
        let mut acc = SseAccumulator::new();
        acc.feed(r#"data: {"choices":[{"delta":{"content":"partial"}}]}"#)
            .unwrap();
        assert!(matches!(
            acc.finish("r", "m", &[]),
            Err(ProviderError::Incomplete(_))
        ));
        let mut acc = SseAccumulator::new();
        for _ in 0..3 {
            acc.feed("data: {broken").unwrap();
        }
        assert!(acc.feed("data: {broken").is_err());
        let mut acc = SseAccumulator::new();
        assert!(acc
            .feed(r#"data: {"error":{"message":"overloaded"}}"#)
            .is_err());
    }
}
