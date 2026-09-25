use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use url::Url;

use crate::{
    endpoint_request_key, insert_parameter_location, passive, query_parameters, CheckConfig,
    EndpointObservation, FindingObservation, ObservedResponse, ParameterLocations,
    RequestSeedContext, ScanConfig, ScanError, ScopePolicy, ScopedRequester, SourceEndpointSeed,
};

pub struct DiscoveryResult {
    pub endpoints: Vec<EndpointObservation>,
    pub findings: Vec<FindingObservation>,
    pub responses: HashMap<String, ObservedResponse>,
    pub request_seeds: HashMap<String, RequestSeedContext>,
}

pub fn crawl(
    policy: &ScopePolicy,
    requester: &ScopedRequester,
    config: &ScanConfig,
    cancelled: Arc<AtomicBool>,
    on_progress: &mut impl FnMut(usize, usize),
) -> Result<DiscoveryResult, ScanError> {
    crawl_with_seeds(
        policy,
        requester,
        config,
        &[],
        cancelled,
        on_progress,
    )
}

pub fn crawl_with_seeds(
    policy: &ScopePolicy,
    requester: &ScopedRequester,
    config: &ScanConfig,
    source_seeds: &[SourceEndpointSeed],
    cancelled: Arc<AtomicBool>,
    on_progress: &mut impl FnMut(usize, usize),
) -> Result<DiscoveryResult, ScanError> {
    let mut queue = VecDeque::new();
    let mut seen = HashSet::new();
    let mut endpoint_keys = HashMap::new();
    let mut endpoints = Vec::new();
    let mut findings = Vec::new();
    let mut responses = HashMap::new();
    let mut request_seeds = HashMap::<String, RequestSeedContext>::new();
    let mut source_seed_by_url = HashMap::<String, SourceEndpointSeed>::new();

    for seed in source_seeds.iter().take(1_000) {
        let Ok(template_url) = policy.normalize_and_assert(&seed.url) else {
            continue;
        };
        let method = seed.method.trim().to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD"
        ) {
            continue;
        }

        if method == "GET" {
            let discovery_raw = seed.discovery_url.as_deref().unwrap_or(&seed.url);
            let Ok(discovery_url) = policy.normalize_and_assert(discovery_raw) else {
                continue;
            };
            let key = normalized_key(&discovery_url);
            source_seed_by_url
                .entry(key)
                .and_modify(|existing| merge_source_seed(existing, seed))
                .or_insert_with(|| seed.clone());
            if discovery_url != *policy.target() {
                queue.push_back((discovery_url, 0, "source_route".to_string(), 0));
            }
            continue;
        }

        let concrete_url = seed
            .discovery_url
            .as_deref()
            .and_then(|raw| policy.normalize_and_assert(raw).ok())
            .unwrap_or_else(|| template_url.clone());
        add_endpoint(
            &mut endpoints,
            &mut endpoint_keys,
            EndpointObservation {
                url: concrete_url.to_string(),
                route_template: Some(template_url.to_string()),
                method,
                depth: 0,
                source: seed.source_label.clone(),
                parameter_names: seed.parameter_names.clone(),
                parameter_locations: seed.parameter_locations.clone(),
                response_header_names: Vec::new(),
                cookie_names: Vec::new(),
                content_type: seed.content_type.clone(),
                status_code: None,
                redirect_to: None,
            },
        );
    }

    // Source-backed GET routes are queued before the generic target so the
    // authorized crawl spends its bounded request budget on known application
    // endpoints first. The ordinary target seed still runs afterwards to
    // discover links/forms/routes that static source analysis did not see.
    queue.push_back((policy.target().clone(), 0usize, "seed".to_string(), 0usize));

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
        let source_seed = source_seed_by_url.get(&normalized);
        let mut parameter_names = query_parameters(&url);
        if let Some(seed) = source_seed {
            parameter_names.extend(seed.parameter_names.clone());
        }
        parameter_names.sort();
        parameter_names.dedup();
        let mut parameter_locations = ParameterLocations::new();
        for name in &parameter_names {
            insert_parameter_location(&mut parameter_locations, name.clone(), "query");
        }
        if let Some(seed) = source_seed {
            for (name, locations) in &seed.parameter_locations {
                for location in locations {
                    insert_parameter_location(
                        &mut parameter_locations,
                        name.clone(),
                        location.clone(),
                    );
                }
            }
        }
        let (response_header_names, cookie_names) = response_inventory(&response);
        let endpoint = EndpointObservation {
            url: url.to_string(),
            route_template: source_seed.map(|seed| seed.url.clone()),
            method: "GET".to_string(),
            depth,
            source: source_seed
                .map(|seed| seed.source_label.clone())
                .unwrap_or(source),
            parameter_names,
            parameter_locations,
            response_header_names,
            cookie_names,
            content_type: source_seed
                .and_then(|seed| seed.content_type.clone())
                .or_else(|| response.content_type.clone()),
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
                        let mut parameter_locations = ParameterLocations::new();
                        for name in &form.parameters {
                            insert_parameter_location(
                                &mut parameter_locations,
                                name.clone(),
                                if form.method == "GET" { "query" } else { "form" },
                            );
                        }
                        let form_endpoint = EndpointObservation {
                            url: form.action.to_string(),
                            route_template: None,
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
                            if !form.hidden_values.is_empty() {
                                let key = endpoint_request_key(&form_endpoint.method, &form_endpoint.url);
                                let context = request_seeds.entry(key).or_default();
                                for name in &form.hidden_names {
                                    context.protected_parameters.push(name.clone());
                                }
                                for (name, value) in &form.hidden_values {
                                    context
                                        .values
                                        .insert(name.clone(), serde_json::Value::String(value.clone()));
                                    if !value.trim().is_empty() && value.len() <= 2_048 {
                                        context.redaction_secrets.push(value.clone());
                                    }
                                }
                                context.protected_parameters.sort();
                                context.protected_parameters.dedup();
                                context.redaction_secrets.sort();
                                context.redaction_secrets.dedup();
                            }
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
                                    let mut parameter_locations = ParameterLocations::new();
                                    for name in &parameter_names {
                                        insert_parameter_location(
                                            &mut parameter_locations,
                                            name.clone(),
                                            "query",
                                        );
                                    }
                                    EndpointObservation {
                                        url: next.to_string(),
                                        route_template: None,
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
                        &mut request_seeds,
                    );
                }
            }
        }
        on_progress(endpoints.len(), findings.len());
    }

    Ok(DiscoveryResult {
        endpoints,
        findings,
        responses,
        request_seeds,
    })
}

#[derive(Debug)]
struct FormObservation {
    action: Url,
    method: String,
    parameters: Vec<String>,
    hidden_names: Vec<String>,
    hidden_values: BTreeMap<String, String>,
}

fn add_endpoint(
    endpoints: &mut Vec<EndpointObservation>,
    keys: &mut HashMap<String, usize>,
    mut endpoint: EndpointObservation,
) {
    normalize_endpoint_metadata(&mut endpoint);
    let key = format!("{} {}", endpoint.method, normalized_url_string(&endpoint.url));
    if let Some(index) = keys.get(&key).copied() {
        if let Some(existing) = endpoints.get_mut(index) {
            merge_endpoint(existing, endpoint);
        }
        return;
    }
    let index = endpoints.len();
    endpoints.push(endpoint);
    keys.insert(key, index);
}

fn normalize_endpoint_metadata(endpoint: &mut EndpointObservation) {
    endpoint.parameter_names.sort();
    endpoint.parameter_names.dedup();
    endpoint.response_header_names.sort();
    endpoint.response_header_names.dedup();
    endpoint.cookie_names.sort();
    endpoint.cookie_names.dedup();
    for locations in endpoint.parameter_locations.values_mut() {
        locations.sort();
        locations.dedup();
    }
}

fn merge_endpoint(existing: &mut EndpointObservation, mut incoming: EndpointObservation) {
    normalize_endpoint_metadata(&mut incoming);
    let incoming_priority = source_priority(&incoming.source);
    let existing_priority = source_priority(&existing.source);
    let incoming_preferred = incoming_priority > existing_priority
        || (incoming_priority == existing_priority && incoming.source < existing.source);

    existing.depth = existing.depth.min(incoming.depth);

    existing.parameter_names.extend(incoming.parameter_names);
    existing.parameter_names.sort();
    existing.parameter_names.dedup();
    for (name, locations) in incoming.parameter_locations {
        for location in locations {
            insert_parameter_location(&mut existing.parameter_locations, name.clone(), location);
        }
    }

    existing
        .response_header_names
        .extend(incoming.response_header_names);
    existing.response_header_names.sort();
    existing.response_header_names.dedup();
    existing.cookie_names.extend(incoming.cookie_names);
    existing.cookie_names.sort();
    existing.cookie_names.dedup();

    if existing.route_template.is_none()
        || (incoming.route_template.is_some() && incoming_preferred)
    {
        existing.route_template = incoming.route_template;
    }
    existing.content_type = merge_content_type(
        existing.content_type.take(),
        incoming.content_type,
        incoming_preferred,
    );
    if existing.status_code.is_none() {
        existing.status_code = incoming.status_code;
    }
    if existing.redirect_to.is_none() {
        existing.redirect_to = incoming.redirect_to;
    }
    if incoming_preferred {
        existing.source = incoming.source;
    }
}

fn merge_content_type(
    existing: Option<String>,
    incoming: Option<String>,
    incoming_preferred: bool,
) -> Option<String> {
    match (existing, incoming) {
        (None, value) | (value, None) => value,
        (Some(left), Some(right)) if left.eq_ignore_ascii_case(&right) => Some(left),
        (Some(_), Some(right)) if incoming_preferred => Some(right),
        (Some(left), Some(_)) => Some(left),
    }
}

fn source_priority(source: &str) -> u8 {
    if source.starts_with("source_route:") {
        5
    } else {
        match source {
            "openapi" => 4,
            "form" => 3,
            "html" | "javascript_reference" => 2,
            "redirect" => 1,
            _ => 0,
        }
    }
}

fn merge_source_seed(existing: &mut SourceEndpointSeed, incoming: &SourceEndpointSeed) {
    existing
        .parameter_names
        .extend(incoming.parameter_names.iter().cloned());
    existing.parameter_names.sort();
    existing.parameter_names.dedup();
    for (name, locations) in &incoming.parameter_locations {
        for location in locations {
            insert_parameter_location(
                &mut existing.parameter_locations,
                name.clone(),
                location.clone(),
            );
        }
    }

    existing.content_type = match (&existing.content_type, &incoming.content_type) {
        (None, value) => value.clone(),
        (Some(_), None) => existing.content_type.clone(),
        (Some(left), Some(right)) if left.eq_ignore_ascii_case(right) => {
            existing.content_type.clone()
        }
        (Some(_), Some(_)) => None,
    };

    let incoming_preferred = incoming.source_label < existing.source_label;
    if incoming_preferred {
        existing.source_label = incoming.source_label.clone();
        existing.url = incoming.url.clone();
        existing.discovery_url = incoming.discovery_url.clone();
    } else if existing.discovery_url.is_none() {
        existing.discovery_url = incoming.discovery_url.clone();
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
            let mut hidden_values = BTreeMap::new();
            for input_tag in tags(body, "input") {
                if let Some(name) = attribute_from_tag(input_tag, "name") {
                    parameters.push(name.clone());
                    if attribute_from_tag(input_tag, "type")
                        .is_some_and(|value| value.eq_ignore_ascii_case("hidden"))
                    {
                        hidden_names.push(name.clone());
                        if let Some(value) = attribute_from_tag(input_tag, "value")
                            .filter(|value| value.len() <= 2_048)
                        {
                            hidden_values.insert(name, value);
                        }
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
            forms.push(FormObservation {
                action,
                method,
                parameters,
                hidden_names,
                hidden_values,
            });
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
    let bytes = tag.as_bytes();
    let target = name.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        while index < bytes.len()
            && (bytes[index].is_ascii_whitespace()
                || matches!(bytes[index], b'<' | b'/' | b'>'))
        {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }

        let name_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && !matches!(bytes[index], b'=' | b'>' | b'/')
        {
            index += 1;
        }
        let attribute_name = &bytes[name_start..index];
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            while index < bytes.len()
                && !bytes[index].is_ascii_whitespace()
                && bytes[index] != b'>'
            {
                index += 1;
            }
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }

        let value_start;
        let value_end;
        if index < bytes.len() && matches!(bytes[index], b'"' | b'\'') {
            let quote = bytes[index];
            index += 1;
            value_start = index;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            value_end = index;
            if index < bytes.len() {
                index += 1;
            }
        } else {
            value_start = index;
            while index < bytes.len()
                && !bytes[index].is_ascii_whitespace()
                && bytes[index] != b'>'
            {
                index += 1;
            }
            value_end = index;
        }

        if attribute_name.eq_ignore_ascii_case(target) {
            return Some(String::from_utf8_lossy(&bytes[value_start..value_end]).trim().to_string());
        }
    }
    None
}

fn discover_openapi(
    policy: &ScopePolicy,
    base: &Url,
    body: &[u8],
    depth: usize,
    endpoints: &mut Vec<EndpointObservation>,
    keys: &mut HashMap<String, usize>,
    request_seeds: &mut HashMap<String, RequestSeedContext>,
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

            let mut parameter_locations = ParameterLocations::new();
            collect_parameter_array(path_item.get("parameters"), &mut parameter_locations);
            collect_parameter_array(operation.get("parameters"), &mut parameter_locations);
            let mut seed_context = RequestSeedContext::default();
            let request_content_type = collect_request_body_parameters(
                operation,
                &mut parameter_locations,
                &mut seed_context,
            );

            let mut parameter_names: Vec<String> = parameter_locations.keys().cloned().collect();
            parameter_names.sort();
            let endpoint = EndpointObservation {
                    url: url.to_string(),
                    route_template: None,
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
                };
            if !seed_context.values.is_empty() {
                request_seeds.insert(
                    endpoint_request_key(&endpoint.method, &endpoint.url),
                    seed_context,
                );
            }
            add_endpoint(endpoints, keys, endpoint);
        }
    }
}

fn collect_parameter_array(
    value: Option<&serde_json::Value>,
    output: &mut ParameterLocations,
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
            insert_parameter_location(output, name.to_string(), location);
        }
    }
}

fn collect_request_body_parameters(
    operation: &serde_json::Value,
    output: &mut ParameterLocations,
    seeds: &mut RequestSeedContext,
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
            for (name, schema) in properties.iter().take(256) {
                insert_parameter_location(output, name.clone(), location);
                if location == "json" {
                    if let Some(seed) = bounded_schema_seed(schema) {
                        seeds.values.entry(name.clone()).or_insert(seed);
                    }
                } else if let Some(seed) = bounded_schema_seed(schema).and_then(seed_to_form_value) {
                    seeds
                        .values
                        .entry(name.clone())
                        .or_insert(serde_json::Value::String(seed));
                }
            }
        }
        return Some(content_type.to_string());
    }
    None
}

fn bounded_schema_seed(schema: &serde_json::Value) -> Option<serde_json::Value> {
    for key in ["default", "example"] {
        if let Some(value) = schema.get(key).and_then(bounded_scalar_value) {
            return Some(value);
        }
    }
    if let Some(value) = schema
        .get("enum")
        .and_then(|value| value.as_array())
        .and_then(|values| values.first())
        .and_then(bounded_scalar_value)
    {
        return Some(value);
    }

    match schema.get("type").and_then(|value| value.as_str()) {
        Some("string") => {
            let value = match schema.get("format").and_then(|value| value.as_str()) {
                Some("email") => "codetwin@example.invalid",
                Some("uuid") => "00000000-0000-4000-8000-000000000001",
                Some("date") => "2000-01-01",
                Some("date-time") => "2000-01-01T00:00:00Z",
                _ => "codetwin-test",
            };
            Some(serde_json::Value::String(value.to_string()))
        }
        Some("integer") => Some(serde_json::Value::Number(serde_json::Number::from(1))),
        Some("number") => serde_json::Number::from_f64(1.0).map(serde_json::Value::Number),
        Some("boolean") => Some(serde_json::Value::Bool(true)),
        _ => None,
    }
}

fn bounded_scalar_value(value: &serde_json::Value) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::String(text) if text.len() <= 256 => Some(value.clone()),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) | serde_json::Value::Null => {
            Some(value.clone())
        }
        _ => None,
    }
}

fn seed_to_form_value(value: serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Null => Some(String::new()),
        _ => None,
    }
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
    use std::collections::HashMap;

    use url::Url;

    use super::{
        add_endpoint, attribute_from_tag, bounded_schema_seed, extract_forms, extract_links,
        merge_source_seed,
    };
    use crate::{
        EndpointObservation, ParameterLocations, SourceEndpointSeed,
    };

    #[test]
    fn duplicate_endpoints_merge_richer_metadata_without_overwrite() {
        let mut endpoints = Vec::new();
        let mut keys = HashMap::new();

        add_endpoint(
            &mut endpoints,
            &mut keys,
            EndpointObservation {
                url: "https://example.test/api/items/1?id=1".into(),
                route_template: Some("https://example.test/api/items/{id}?id=1".into()),
                method: "GET".into(),
                depth: 0,
                source: "source_route:express:src/routes.ts:10".into(),
                parameter_names: vec!["id".into()],
                parameter_locations: ParameterLocations::from([(
                    "id".into(),
                    vec!["path".into()],
                )]),
                response_header_names: Vec::new(),
                cookie_names: Vec::new(),
                content_type: Some("application/json".into()),
                status_code: None,
                redirect_to: None,
            },
        );
        add_endpoint(
            &mut endpoints,
            &mut keys,
            EndpointObservation {
                url: "https://example.test/api/items/1?id=1#fragment".into(),
                route_template: None,
                method: "GET".into(),
                depth: 2,
                source: "openapi".into(),
                parameter_names: vec!["id".into(), "q".into()],
                parameter_locations: ParameterLocations::from([
                    ("id".into(), vec!["query".into()]),
                    ("q".into(), vec!["query".into()]),
                ]),
                response_header_names: vec!["content-type".into()],
                cookie_names: vec!["session".into()],
                content_type: None,
                status_code: Some(200),
                redirect_to: None,
            },
        );

        assert_eq!(endpoints.len(), 1);
        let endpoint = &endpoints[0];
        assert_eq!(endpoint.depth, 0);
        assert_eq!(
            endpoint.parameter_names,
            vec!["id".to_string(), "q".to_string()]
        );
        assert_eq!(
            endpoint.parameter_locations.get("id"),
            Some(&vec!["path".to_string(), "query".to_string()])
        );
        assert_eq!(
            endpoint.parameter_locations.get("q"),
            Some(&vec!["query".to_string()])
        );
        assert_eq!(endpoint.response_header_names, vec!["content-type".to_string()]);
        assert_eq!(endpoint.cookie_names, vec!["session".to_string()]);
        assert_eq!(endpoint.content_type.as_deref(), Some("application/json"));
        assert_eq!(endpoint.status_code, Some(200));
        assert!(endpoint.source.starts_with("source_route:"));
        assert!(endpoint.route_template.is_some());
    }

    #[test]
    fn duplicate_get_source_seeds_union_parameters_and_fail_closed_on_content_type_conflict() {
        let mut existing = SourceEndpointSeed {
            url: "https://example.test/api/items/{id}".into(),
            discovery_url: Some("https://example.test/api/items/1".into()),
            method: "GET".into(),
            parameter_names: vec!["id".into()],
            parameter_locations: ParameterLocations::from([(
                "id".into(),
                vec!["path".into()],
            )]),
            content_type: Some("application/json".into()),
            source_label: "source_route:express:a.ts:1".into(),
        };
        let incoming = SourceEndpointSeed {
            url: "https://example.test/api/items/{id}".into(),
            discovery_url: Some("https://example.test/api/items/1".into()),
            method: "GET".into(),
            parameter_names: vec!["id".into(), "filter".into()],
            parameter_locations: ParameterLocations::from([
                ("id".into(), vec!["query".into()]),
                ("filter".into(), vec!["query".into()]),
            ]),
            content_type: Some("application/x-www-form-urlencoded".into()),
            source_label: "source_route:express:b.ts:2".into(),
        };

        merge_source_seed(&mut existing, &incoming);

        assert_eq!(
            existing.parameter_names,
            vec!["filter".to_string(), "id".to_string()]
        );
        assert_eq!(
            existing.parameter_locations.get("id"),
            Some(&vec!["path".to_string(), "query".to_string()])
        );
        assert_eq!(
            existing.parameter_locations.get("filter"),
            Some(&vec!["query".to_string()])
        );
        assert!(
            existing.content_type.is_none(),
            "conflicting request content types must not be guessed"
        );
    }

    #[test]
    fn extracts_links_and_forms_without_executing_html() {
        let base = Url::parse("http://localhost:8080/app/").expect("base");
        let html = r#"<a href="/app/users?id=1">Users</a>
            <form data-action="/wrong" action="/app/search" method="post">
              <input type="hidden" data-name="wrong" name="csrf_token" value="csrf-secret-123">
              <input name="q">
            </form>"#;
        let links = extract_links(&base, html);
        assert!(links.iter().any(|url| url.as_str().contains("/app/users?id=1")));
        let forms = extract_forms(&base, html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].action.path(), "/app/search");
        assert_eq!(forms[0].parameters, vec!["csrf_token", "q"]);
        assert_eq!(forms[0].hidden_names, vec!["csrf_token"]);
        assert_eq!(
            forms[0].hidden_values.get("csrf_token").map(String::as_str),
            Some("csrf-secret-123")
        );
        assert_eq!(attribute_from_tag(r#"<a href="/x">"#, "href").as_deref(), Some("/x"));
        assert_eq!(
            attribute_from_tag(r#"<form data-action="/wrong" action="/right">"#, "action")
                .as_deref(),
            Some("/right")
        );
        assert!(
            attribute_from_tag(r#"<input data-name="wrong" value="x">"#, "name").is_none(),
            "data-name must not be mistaken for name"
        );
    }

    #[test]
    fn openapi_scalar_seed_values_preserve_simple_json_types() {
        assert_eq!(
            bounded_schema_seed(&serde_json::json!({"type":"integer"})),
            Some(serde_json::json!(1))
        );
        assert_eq!(
            bounded_schema_seed(&serde_json::json!({"type":"boolean"})),
            Some(serde_json::json!(true))
        );
        assert_eq!(
            bounded_schema_seed(&serde_json::json!({"type":"string","format":"email"})),
            Some(serde_json::json!("codetwin@example.invalid"))
        );
        assert_eq!(
            bounded_schema_seed(&serde_json::json!({"type":"object"})),
            None,
            "complex request shapes must remain fail-closed instead of being guessed"
        );
    }
}
