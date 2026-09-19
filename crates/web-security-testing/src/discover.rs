use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use url::Url;

use crate::{
    passive, query_parameters, CheckConfig, EndpointObservation, FindingObservation,
    ObservedResponse, ScanConfig, ScanError, ScopePolicy, ScopedRequester,
};

pub struct DiscoveryResult {
    pub endpoints: Vec<EndpointObservation>,
    pub findings: Vec<FindingObservation>,
    pub responses: HashMap<String, ObservedResponse>,
}

pub fn crawl(
    policy: &ScopePolicy,
    requester: &ScopedRequester,
    config: &ScanConfig,
    cancelled: Arc<AtomicBool>,
    on_progress: &mut impl FnMut(usize, usize),
) -> Result<DiscoveryResult, ScanError> {
    let mut queue = VecDeque::from([(policy.target().clone(), 0usize, "seed".to_string(), 0usize)]);
    let mut seen = HashSet::new();
    let mut endpoint_keys = HashSet::new();
    let mut endpoints = Vec::new();
    let mut findings = Vec::new();
    let mut responses = HashMap::new();

    while let Some((url, depth, source, redirects)) = queue.pop_front() {
        if cancelled.load(Ordering::SeqCst) {
            return Err(ScanError::Cancelled);
        }
        if depth > policy.config().max_crawl_depth {
            continue;
        }
        let normalized = normalized_key(&url);
        if !seen.insert(normalized.clone()) {
            continue;
        }

        let response = match requester.get(&url) {
            Ok(value) => value,
            Err(crate::RequestError::BudgetExhausted) => break,
            Err(crate::RequestError::Cancelled) => return Err(ScanError::Cancelled),
            Err(_) => continue,
        };
        let parameter_names = query_parameters(&url);
        let parameter_locations = parameter_names
            .iter()
            .map(|name| (name.clone(), "query".to_string()))
            .collect();
        let (response_header_names, cookie_names) = response_inventory(&response);
        let endpoint = EndpointObservation {
            url: url.to_string(),
            method: "GET".to_string(),
            depth,
            source,
            parameter_names,
            parameter_locations,
            response_header_names,
            cookie_names,
            content_type: response.content_type.clone(),
            status_code: Some(response.status),
            redirect_to: response.location.clone(),
        };
        add_endpoint(&mut endpoints, &mut endpoint_keys, endpoint.clone());

        findings.extend(passive::analyze_response(
            &url,
            &endpoint,
            &response,
            &config.checks,
        ));

        if (300..400).contains(&response.status) {
            if let Some(location) = response.location.as_deref() {
                if redirects < policy.config().redirect_limit {
                    if let Ok(next) = resolve_url(&url, location) {
                        if policy.assert_url(&next).is_ok() {
                            queue.push_back((next, depth, "redirect".to_string(), redirects + 1));
                        }
                    }
                }
            }
        } else {
            responses.insert(normalized.clone(), response.clone());
            if depth < policy.config().max_crawl_depth {
                let content_type = response.content_type.as_deref().unwrap_or("").to_ascii_lowercase();
                if content_type.contains("text/html") {
                    let body = String::from_utf8_lossy(&response.body);
                    for next in extract_links(&url, &body) {
                        if policy.assert_url(&next).is_ok() {
                            queue.push_back((next, depth + 1, "html".to_string(), 0));
                        }
                    }
                    let forms = extract_forms(&url, &body);
                    for form in forms {
                        let parameter_locations = form
                            .parameters
                            .iter()
                            .map(|name| (name.clone(), if form.method == "GET" { "query" } else { "form" }.to_string()))
                            .collect();
                        let form_endpoint = EndpointObservation {
                            url: form.action.to_string(),
                            method: form.method.clone(),
                            depth: depth + 1,
                            source: "form".to_string(),
                            parameter_names: form.parameters.clone(),
                            parameter_locations,
                            response_header_names: Vec::new(),
                            cookie_names: Vec::new(),
                            content_type: if form.method == "GET" { None } else { Some("application/x-www-form-urlencoded".to_string()) },
                            status_code: None,
                            redirect_to: None,
                        };
                        if policy.assert_url(&form.action).is_ok() {
                            findings.extend(passive::analyze_form(
                                &form.action,
                                &form_endpoint,
                                &form.hidden_names,
                                &config.checks,
                            ));
                            add_endpoint(&mut endpoints, &mut endpoint_keys, form_endpoint);
                        }
                    }
                    for next in extract_script_references(&url, &body) {
                        if policy.assert_url(&next).is_ok() {
                            add_endpoint(
                                &mut endpoints,
                                &mut endpoint_keys,
                                {
                                    let parameter_names = query_parameters(&next);
                                    let parameter_locations = parameter_names
                                        .iter()
                                        .map(|name| (name.clone(), "query".to_string()))
                                        .collect();
                                    EndpointObservation {
                                        url: next.to_string(),
                                        method: "GET".to_string(),
                                        depth: depth + 1,
                                        source: "javascript_reference".to_string(),
                                        parameter_names,
                                        parameter_locations,
                                        response_header_names: Vec::new(),
                                        cookie_names: Vec::new(),
                                        content_type: None,
                                        status_code: None,
                                        redirect_to: None,
                                    }
                                },
                            );
                        }
                    }
                } else if content_type.contains("application/json") {
                    discover_openapi(
                        policy,
                        &url,
                        &response.body,
                        depth,
                        &mut endpoints,
                        &mut endpoint_keys,
                    );
                }
            }
        }
        on_progress(endpoints.len(), findings.len());
    }

    Ok(DiscoveryResult { endpoints, findings, responses })
}

#[derive(Debug)]
struct FormObservation {
    action: Url,
    method: String,
    parameters: Vec<String>,
    hidden_names: Vec<String>,
}

fn add_endpoint(
    endpoints: &mut Vec<EndpointObservation>,
    keys: &mut HashSet<String>,
    mut endpoint: EndpointObservation,
) {
    endpoint.parameter_names.sort();
    endpoint.parameter_names.dedup();
    let key = format!("{} {}", endpoint.method, normalized_url_string(&endpoint.url));
    if keys.insert(key) {
        endpoints.push(endpoint);
    }
}

fn normalized_key(url: &Url) -> String {
    let mut value = url.clone();
    value.set_fragment(None);
    value.to_string()
}

fn normalized_url_string(raw: &str) -> String {
    Url::parse(raw).map(|value| normalized_key(&value)).unwrap_or_else(|_| raw.to_string())
}

fn resolve_url(base: &Url, value: &str) -> Result<Url, url::ParseError> {
    if value.starts_with("http://") || value.starts_with("https://") {
        Url::parse(value)
    } else {
        base.join(value)
    }
}

fn extract_links(base: &Url, html: &str) -> Vec<Url> {
    let mut output = Vec::new();
    for attribute in ["href", "src", "action"] {
        for value in attribute_values(html, attribute) {
            if value.starts_with('#')
                || value.starts_with("javascript:")
                || value.starts_with("mailto:")
                || value.starts_with("data:")
            {
                continue;
            }
            if let Ok(url) = resolve_url(base, &value) {
                if matches!(url.scheme(), "http" | "https") {
                    output.push(url);
                }
            }
        }
    }
    output.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    output.dedup_by(|left, right| left.as_str() == right.as_str());
    output
}

fn extract_script_references(base: &Url, html: &str) -> Vec<Url> {
    let mut output = Vec::new();
    for quote in ['"', '\''] {
        for chunk in html.split(quote) {
            let candidate = chunk.trim();
            let looks_like_endpoint = candidate.starts_with("/api/")
                || candidate.starts_with("/v1/")
                || candidate.starts_with("/v2/")
                || candidate.starts_with("http://")
                || candidate.starts_with("https://");
            if looks_like_endpoint && candidate.len() <= 2_048 {
                if let Ok(url) = resolve_url(base, candidate) {
                    output.push(url);
                }
            }
        }
    }
    output.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    output.dedup_by(|left, right| left.as_str() == right.as_str());
    output.truncate(256);
    output
}

fn extract_forms(base: &Url, html: &str) -> Vec<FormObservation> {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut forms = Vec::new();
    while let Some(relative) = lower[cursor..].find("<form") {
        let start = cursor + relative;
        let Some(tag_end_relative) = lower[start..].find('>') else { break };
        let tag_end = start + tag_end_relative + 1;
        let Some(close_relative) = lower[tag_end..].find("</form>") else { break };
        let close = tag_end + close_relative;
        let tag = &html[start..tag_end];
        let body = &html[tag_end..close];
        let action = attribute_from_tag(tag, "action").unwrap_or_else(|| base.path().to_string());
        let method = attribute_from_tag(tag, "method")
            .unwrap_or_else(|| "GET".to_string())
            .to_ascii_uppercase();
        if let Ok(action) = resolve_url(base, &action) {
            let mut parameters = Vec::new();
            let mut hidden_names = Vec::new();
            for input_tag in tags(body, "input") {
                if let Some(name) = attribute_from_tag(input_tag, "name") {
                    parameters.push(name.clone());
                    if attribute_from_tag(input_tag, "type")
                        .is_some_and(|value| value.eq_ignore_ascii_case("hidden"))
                    {
                        hidden_names.push(name);
                    }
                }
            }
            for select_tag in tags(body, "select") {
                if let Some(name) = attribute_from_tag(select_tag, "name") {
                    parameters.push(name);
                }
            }
            for textarea_tag in tags(body, "textarea") {
                if let Some(name) = attribute_from_tag(textarea_tag, "name") {
                    parameters.push(name);
                }
            }
            parameters.sort();
            parameters.dedup();
            forms.push(FormObservation { action, method, parameters, hidden_names });
        }
        cursor = close + "</form>".len();
    }
    forms
}

fn tags<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
    let lower = html.to_ascii_lowercase();
    let needle = format!("<{name}");
    let mut cursor = 0usize;
    let mut output = Vec::new();
    while let Some(relative) = lower[cursor..].find(&needle) {
        let start = cursor + relative;
        let Some(end_relative) = lower[start..].find('>') else { break };
        let end = start + end_relative + 1;
        output.push(&html[start..end]);
        cursor = end;
    }
    output
}

fn attribute_values(html: &str, attribute: &str) -> Vec<String> {
    let mut values = Vec::new();
    for tag_name in ["a", "link", "script", "img", "form"] {
        for tag in tags(html, tag_name) {
            if let Some(value) = attribute_from_tag(tag, attribute) {
                values.push(value);
            }
        }
    }
    values
}

fn attribute_from_tag(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{name}=");
    let index = lower.find(&needle)? + needle.len();
    let rest = tag[index..].trim_start();
    let first = rest.chars().next()?;
    if matches!(first, '"' | '\'') {
        let tail = &rest[first.len_utf8()..];
        let end = tail.find(first)?;
        Some(tail[..end].trim().to_string())
    } else {
        let end = rest.find(|character: char| character.is_whitespace() || character == '>').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

fn discover_openapi(
    policy: &ScopePolicy,
    base: &Url,
    body: &[u8],
    depth: usize,
    endpoints: &mut Vec<EndpointObservation>,
    keys: &mut HashSet<String>,
) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else { return };
    if value.get("openapi").is_none() && value.get("swagger").is_none() {
        return;
    }
    let Some(paths) = value.get("paths").and_then(|value| value.as_object()) else { return };
    for (path, path_item) in paths.iter().take(500) {
        let Ok(url) = base.join(path) else { continue };
        if policy.assert_url(&url).is_err() {
            continue;
        }
        let Some(methods) = path_item.as_object() else { continue };
        for (method, operation) in methods {
            let method_upper = method.to_ascii_uppercase();
            if !matches!(method_upper.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD") {
                continue;
            }

            let mut parameter_locations = BTreeMap::new();
            collect_parameter_array(path_item.get("parameters"), &mut parameter_locations);
            collect_parameter_array(operation.get("parameters"), &mut parameter_locations);
            let request_content_type = collect_request_body_parameters(operation, &mut parameter_locations);

            let mut parameter_names: Vec<String> = parameter_locations.keys().cloned().collect();
            parameter_names.sort();
            add_endpoint(
                endpoints,
                keys,
                EndpointObservation {
                    url: url.to_string(),
                    method: method_upper,
                    depth: depth + 1,
                    source: "openapi".to_string(),
                    parameter_names,
                    parameter_locations,
                    response_header_names: Vec::new(),
                    cookie_names: Vec::new(),
                    content_type: request_content_type,
                    status_code: None,
                    redirect_to: None,
                },
            );
        }
    }
}

fn collect_parameter_array(
    value: Option<&serde_json::Value>,
    output: &mut BTreeMap<String, String>,
) {
    let Some(values) = value.and_then(|value| value.as_array()) else { return };
    for parameter in values.iter().take(256) {
        let Some(name) = parameter.get("name").and_then(|value| value.as_str()) else { continue };
        let location = parameter
            .get("in")
            .and_then(|value| value.as_str())
            .unwrap_or("query")
            .to_ascii_lowercase();
        if matches!(location.as_str(), "query" | "path" | "header" | "cookie") {
            output.insert(name.to_string(), location);
        }
    }
}

fn collect_request_body_parameters(
    operation: &serde_json::Value,
    output: &mut BTreeMap<String, String>,
) -> Option<String> {
    let content = operation
        .get("requestBody")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_object())?;

    for (content_type, location) in [
        ("application/json", "json"),
        ("application/x-www-form-urlencoded", "form"),
        ("multipart/form-data", "form"),
    ] {
        let Some(media) = content.get(content_type) else { continue };
        if let Some(properties) = media
            .get("schema")
            .and_then(|value| value.get("properties"))
            .and_then(|value| value.as_object())
        {
            for name in properties.keys().take(256) {
                output.insert(name.clone(), location.to_string());
            }
        }
        return Some(content_type.to_string());
    }
    None
}

fn response_inventory(response: &ObservedResponse) -> (Vec<String>, Vec<String>) {
    let mut header_names: Vec<String> = response
        .headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    header_names.sort();
    header_names.dedup();

    let mut cookie_names: Vec<String> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, value)| value.split('=').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect();
    cookie_names.sort();
    cookie_names.dedup();
    (header_names, cookie_names)
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{attribute_from_tag, extract_forms, extract_links};

    #[test]
    fn extracts_links_and_forms_without_executing_html() {
        let base = Url::parse("http://localhost:8080/app/").expect("base");
        let html = r#"<a href="/app/users?id=1">Users</a>
            <form action="/app/search" method="post">
              <input type="hidden" name="csrf_token">
              <input name="q">
            </form>"#;
        let links = extract_links(&base, html);
        assert!(links.iter().any(|url| url.as_str().contains("/app/users?id=1")));
        let forms = extract_forms(&base, html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].parameters, vec!["csrf_token", "q"]);
        assert_eq!(forms[0].hidden_names, vec!["csrf_token"]);
        assert_eq!(attribute_from_tag(r#"<a href="/x">"#, "href").as_deref(), Some("/x"));
    }
}
