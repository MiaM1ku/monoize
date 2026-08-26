//! Channel probing: upstream model-list discovery and one-shot completion
//! probes with normalized error reporting.

use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::time::Duration;
use super::*;

pub async fn probe_channel_list_models(
    client: &reqwest::Client,
    channel: &MonoizeChannel,
    timeout_ms: u64,
) -> bool {
    let base = channel.base_url.trim_end_matches('/');
    let url = format!("{base}/v1/models");

    let result = client
        .get(url)
        .timeout(Duration::from_millis(timeout_ms))
        .bearer_auth(&channel.api_key)
        .send()
        .await;

    match result {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Resolves the effective API type for a given model by evaluating api_type_overrides

pub struct ChannelProbeOutcome {
    pub ok: bool,
    pub usage: Option<Value>,
    pub http_status: Option<u16>,
    pub error_code: Option<String>,
    pub error_type: Option<String>,
    pub error: Option<String>,
}

const PROBE_ERROR_BODY_MAX_CHARS: usize = 512;

fn truncate_probe_body(body: &str) -> String {
    let body = body.trim();
    if body.chars().count() <= PROBE_ERROR_BODY_MAX_CHARS {
        return body.to_string();
    }
    let truncated: String = body.chars().take(PROBE_ERROR_BODY_MAX_CHARS).collect();
    format!("{truncated}…")
}

pub fn format_probe_http_error(status: reqwest::StatusCode, body: &str) -> String {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("");
    let body = truncate_probe_body(body);
    if body.is_empty() {
        if reason.is_empty() {
            format!("upstream returned {code}")
        } else {
            format!("upstream returned {code} {reason}")
        }
    } else if reason.is_empty() {
        format!("upstream returned {code}: {body}")
    } else {
        format!("upstream returned {code} {reason}: {body}")
    }
}

fn probe_error_metadata(body: &str) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (None, None);
    };
    let error = value.get("error").unwrap_or(&value);
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let error_type = error
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    (code, error_type)
}

fn probe_stream_error(
    value: &Value,
    sse_event: &str,
) -> Option<(Option<String>, Option<String>, String)> {
    let event_type = value.get("type").and_then(Value::as_str);
    let error = value.get("error");
    if error.is_none()
        && !matches!(
            event_type,
            Some("error" | "response.failed" | "response.incomplete")
        )
        && !matches!(
            sse_event,
            "error" | "response.failed" | "response.incomplete"
        )
    {
        return None;
    }
    let detail = error.unwrap_or(value);
    let code = detail
        .get("code")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let error_type = detail
        .get("type")
        .and_then(Value::as_str)
        .or(event_type)
        .or_else(|| (!sse_event.is_empty()).then_some(sse_event))
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let message = detail
        .get("message")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| truncate_probe_body(&detail.to_string()));
    Some((
        code,
        error_type,
        format!("upstream stream error: {message}"),
    ))
}

async fn read_probe_stream(
    response: reqwest::Response,
    effective_type: MonoizeProviderType,
) -> ChannelProbeOutcome {
    let status = response.status().as_u16();
    let mut usage = None;
    let mut chat_terminal_chunk_seen = false;
    let mut stream = response.bytes_stream().eventsource();

    while let Some(event) = stream.next().await {
        let event = match event {
            Ok(event) => event,
            Err(error) => {
                return ChannelProbeOutcome {
                    ok: false,
                    usage,
                    http_status: Some(status),
                    error_code: Some("upstream_stream_decode_failed".to_string()),
                    error_type: Some("stream_error".to_string()),
                    error: Some(format!("upstream stream decode failed: {error}")),
                };
            }
        };
        let data = event.data.trim();
        if data.is_empty() {
            continue;
        }
        if data == "[DONE]" {
            if effective_type != MonoizeProviderType::ChatCompletion || !chat_terminal_chunk_seen {
                return ChannelProbeOutcome {
                    ok: false,
                    usage,
                    http_status: Some(status),
                    error_code: Some("upstream_stream_missing_terminal".to_string()),
                    error_type: Some("stream_error".to_string()),
                    error: Some(format!(
                        "upstream {} stream sent [DONE] before its terminal event",
                        effective_type.as_str()
                    )),
                };
            }
            return ChannelProbeOutcome {
                ok: true,
                usage,
                http_status: Some(status),
                error_code: None,
                error_type: None,
                error: None,
            };
        }

        let value = match serde_json::from_str::<Value>(data) {
            Ok(value) => value,
            Err(error) => {
                return ChannelProbeOutcome {
                    ok: false,
                    usage,
                    http_status: Some(status),
                    error_code: Some("upstream_stream_decode_failed".to_string()),
                    error_type: Some("stream_error".to_string()),
                    error: Some(format!(
                        "upstream stream event contains invalid JSON: {error}: {}",
                        truncate_probe_body(data)
                    )),
                };
            }
        };
        if let Some(stream_usage) = extract_probe_usage(&value) {
            usage = Some(stream_usage);
        }
        if let Some((error_code, error_type, error)) = probe_stream_error(&value, &event.event) {
            return ChannelProbeOutcome {
                ok: false,
                usage,
                http_status: Some(status),
                error_code,
                error_type,
                error: Some(error),
            };
        }

        let event_type = value.get("type").and_then(Value::as_str);
        match effective_type {
            MonoizeProviderType::Responses => {
                if event.event == "response.completed" || event_type == Some("response.completed") {
                    return ChannelProbeOutcome {
                        ok: true,
                        usage,
                        http_status: Some(status),
                        error_code: None,
                        error_type: None,
                        error: None,
                    };
                }
            }
            MonoizeProviderType::ChatCompletion => {
                chat_terminal_chunk_seen |= value
                    .get("choices")
                    .and_then(Value::as_array)
                    .is_some_and(|choices| {
                        choices.iter().any(|choice| {
                            choice
                                .get("finish_reason")
                                .is_some_and(|reason| !reason.is_null())
                        })
                    });
            }
            MonoizeProviderType::Messages => {
                if event.event == "message_stop" || event_type == Some("message_stop") {
                    return ChannelProbeOutcome {
                        ok: true,
                        usage,
                        http_status: Some(status),
                        error_code: None,
                        error_type: None,
                        error: None,
                    };
                }
            }
            MonoizeProviderType::Gemini => {
                let terminal = value
                    .get("candidates")
                    .and_then(Value::as_array)
                    .is_some_and(|candidates| {
                        candidates.iter().any(|candidate| {
                            candidate
                                .get("finishReason")
                                .is_some_and(|reason| !reason.is_null())
                        })
                    });
                if terminal {
                    return ChannelProbeOutcome {
                        ok: true,
                        usage,
                        http_status: Some(status),
                        error_code: None,
                        error_type: None,
                        error: None,
                    };
                }
            }
            MonoizeProviderType::OpenaiImage | MonoizeProviderType::Replicate => {}
        }
    }

    ChannelProbeOutcome {
        ok: false,
        usage,
        http_status: Some(status),
        error_code: Some("upstream_stream_missing_terminal".to_string()),
        error_type: Some("stream_error".to_string()),
        error: Some(format!(
            "upstream {} stream ended without a terminal event",
            effective_type.as_str()
        )),
    }
}

pub async fn probe_channel_completion(
    client: &reqwest::Client,
    channel: &MonoizeChannel,
    timeout_ms: u64,
    model: &str,
    provider_type: MonoizeProviderType,
    api_type_overrides: &[ApiTypeOverride],
    stream: bool,
) -> ChannelProbeOutcome {
    let effective_type = resolve_effective_api_type(api_type_overrides, provider_type, model);
    let base = channel.base_url.trim_end_matches('/');
    let (url, body, extra_headers, use_google_api_key_header) =
        build_probe_request(base, model, effective_type, stream);

    let mut request = client.post(&url).timeout(Duration::from_millis(timeout_ms));
    request = if use_google_api_key_header {
        request.header("x-goog-api-key", &channel.api_key)
    } else {
        request.bearer_auth(&channel.api_key)
    };
    for &(header_name, header_value) in extra_headers {
        request = request.header(header_name, header_value);
    }
    if let Some(channel_headers) = &channel.extra_headers {
        for (header_name, header_value) in channel_headers {
            request = request.header(header_name, header_value);
        }
    }
    let result = request.json(&body).send().await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                let (error_code, error_type) = probe_error_metadata(&body);
                return ChannelProbeOutcome {
                    ok: false,
                    usage: None,
                    http_status: Some(status.as_u16()),
                    error_code,
                    error_type,
                    error: Some(format_probe_http_error(status, &body)),
                };
            }
            if stream {
                return read_probe_stream(resp, effective_type).await;
            }
            let usage = match resp.json::<Value>().await {
                Ok(value) => extract_probe_usage(&value),
                Err(_) => None,
            };
            ChannelProbeOutcome {
                ok: true,
                usage,
                http_status: Some(status.as_u16()),
                error_code: None,
                error_type: None,
                error: None,
            }
        }
        Err(error) => ChannelProbeOutcome {
            ok: false,
            usage: None,
            http_status: None,
            error_code: Some("upstream_connection_failed".to_string()),
            error_type: Some("transport_error".to_string()),
            error: Some(format!("connection failed: {error}")),
        },
    }
}

pub(super) fn build_probe_request(
    base: &str,
    model: &str,
    effective_type: MonoizeProviderType,
    stream: bool,
) -> (String, Value, &'static [(&'static str, &'static str)], bool) {
    match effective_type {
        MonoizeProviderType::Responses => {
            let url = format!("{base}/v1/responses");
            let body = serde_json::json!({
                "model": model,
                "max_output_tokens": 16,
                "stream": stream,
                "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]}]
            });
            (url, body, &[][..], false)
        }
        MonoizeProviderType::ChatCompletion => {
            let url = format!("{base}/v1/chat/completions");
            let body = serde_json::json!({
                "model": model,
                "max_tokens": 16,
                "stream": stream,
                "messages": [{"role": "user", "content": "hi"}]
            });
            (url, body, &[][..], false)
        }
        MonoizeProviderType::Messages => {
            let url = format!("{base}/v1/messages");
            let body = serde_json::json!({
                "model": model,
                "max_tokens": 16,
                "stream": stream,
                "messages": [{"role": "user", "content": "hi"}]
            });
            (url, body, &[("anthropic-version", "2023-06-01")][..], false)
        }
        MonoizeProviderType::Gemini => {
            let method = if stream {
                "streamGenerateContent?alt=sse"
            } else {
                "generateContent"
            };
            let url = format!("{base}/v1beta/models/{model}:{method}");
            let body = serde_json::json!({
                "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
                "generationConfig": {"maxOutputTokens": 16}
            });
            (url, body, &[][..], true)
        }
        MonoizeProviderType::OpenaiImage => {
            let url = format!("{base}/v1/images/generations");
            let body = serde_json::json!({
                "model": model,
                "prompt": "test",
                "size": "1024x1024",
                "n": 1,
            });
            (url, body, &[][..], false)
        }
        MonoizeProviderType::Replicate => {
            // Replicate providers are excluded from active probing; this is a
            // fallback that should never be reached.
            let url = format!("{base}/v1/predictions");
            let body = serde_json::json!({
                "version": model,
                "input": {}
            });
            (url, body, &[][..], false)
        }
    }
}

pub(super) fn extract_probe_usage(body: &Value) -> Option<Value> {
    if let Some(usage) = body.get("usage") {
        let prompt_tokens = usage
            .get("prompt_tokens")
            .and_then(Value::as_u64)
            .or_else(|| usage.get("input_tokens").and_then(Value::as_u64));
        let completion_tokens = usage
            .get("completion_tokens")
            .and_then(Value::as_u64)
            .or_else(|| usage.get("output_tokens").and_then(Value::as_u64));

        if let (Some(prompt_tokens), Some(completion_tokens)) = (prompt_tokens, completion_tokens) {
            return Some(
                json!({"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}),
            );
        }
    }

    let usage = body.get("usageMetadata")?;
    let prompt_tokens = usage
        .get("promptTokenCount")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("input_tokens").and_then(Value::as_u64));
    let completion_tokens = usage
        .get("candidatesTokenCount")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("output_tokens").and_then(Value::as_u64));

    match (prompt_tokens, completion_tokens) {
        (Some(prompt_tokens), Some(completion_tokens)) => {
            Some(json!({"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}))
        }
        _ => None,
    }
}
