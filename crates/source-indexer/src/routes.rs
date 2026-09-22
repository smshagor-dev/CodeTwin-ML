use std::collections::BTreeMap;

use tree_sitter::Node;

use crate::{IndexedHandlerInput, IndexedRoute, IndexedRouteMount, IndexedRouteParameter};

const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "options", "head"];

pub fn extract_routes(
    language: &str,
    relative_path: &str,
    source: &str,
    root: Node<'_>,
) -> (
    Vec<IndexedRoute>,
    Vec<IndexedRouteMount>,
    Vec<IndexedHandlerInput>,
) {
    let (mut routes, mut mounts, mut handler_inputs) = match language {
        "JavaScript" | "TypeScript" | "TypeScript TSX" => {
            let (mut routes, mounts) = extract_express_routes(source, root);
            routes.extend(extract_nextjs_app_routes(relative_path, source, root));
            let mut handler_inputs = javascript_handler_inputs(source, root);
            handler_inputs.extend(nextjs_handler_inputs(relative_path, source, root));
            (routes, mounts, handler_inputs)
        }
        "Python" => {
            let (mut routes, mut mounts) = extract_fastapi_routes(source, root);
            let (flask_routes, flask_mounts, flask_inputs) = extract_flask_routes(source, root);
            routes.extend(flask_routes);
            mounts.extend(flask_mounts);
            (routes, mounts, flask_inputs)
        }
        "PHP" => {
            let (routes, mounts) = extract_laravel_routes(source, root);
            (routes, mounts, Vec::new())
        }
        "Go" => {
            let (routes, mounts, handler_inputs) = extract_go_routes(source, root);
            (routes, mounts, handler_inputs)
        }
        "Rust" => {
            let (routes, handler_inputs) = extract_rust_routes(source, root);
            (routes, Vec::new(), handler_inputs)
        }
        _ => (Vec::new(), Vec::new(), Vec::new()),
    };
    routes.sort_by(|left, right| {
        (
            &left.path_template,
            &left.http_method,
            left.start_line,
            &left.router_name,
        )
            .cmp(&(
                &right.path_template,
                &right.http_method,
                right.start_line,
                &right.router_name,
            ))
    });
    routes.dedup_by(|left, right| {
        left.path_template == right.path_template
            && left.http_method == right.http_method
            && left.start_line == right.start_line
            && left.router_name == right.router_name
    });
    mounts.sort_by(|left, right| {
        (
            &left.parent_router,
            &left.prefix,
            &left.mounted_binding,
            left.start_line,
        )
            .cmp(&(
                &right.parent_router,
                &right.prefix,
                &right.mounted_binding,
                right.start_line,
            ))
    });
    mounts.dedup_by(|left, right| {
        left.framework == right.framework
            && left.parent_router == right.parent_router
            && left.mounted_binding == right.mounted_binding
            && left.prefix == right.prefix
            && left.start_line == right.start_line
    });
    handler_inputs.sort_by(|left, right| {
        (&left.handler_name, left.start_line, left.end_line)
            .cmp(&(&right.handler_name, right.start_line, right.end_line))
    });
    let mut merged_handler_inputs: Vec<IndexedHandlerInput> = Vec::new();
    for mut input in handler_inputs {
        normalize_parameters(&mut input.parameters);
        if let Some(last) = merged_handler_inputs.last_mut() {
            if last.handler_name == input.handler_name
                && last.start_line == input.start_line
                && last.end_line == input.end_line
            {
                last.parameters.extend(input.parameters);
                normalize_parameters(&mut last.parameters);
                continue;
            }
        }
        merged_handler_inputs.push(input);
    }
    (routes, mounts, merged_handler_inputs)
}

fn extract_nextjs_app_routes(
    relative_path: &str,
    source: &str,
    root: Node<'_>,
) -> Vec<IndexedRoute> {
    let Some(path_template) = nextjs_app_route_path(relative_path) else {
        return Vec::new();
    };
    let handlers = javascript_handlers(source, root);
    let mut routes = Vec::new();
    walk(root, &mut |node| {
        if node.kind() != "export_statement" {
            return;
        }
        let Some(value) = text(source, node) else {
            return;
        };
        let exported = nextjs_exported_http_handlers(value);
        if exported.is_empty() {
            return;
        }
        let start = node.start_position();
        let end = node.end_position();
        for (method, local_handler) in exported {
            let mut parameters = path_parameters(&path_template);
            if let Some(handler) = handlers.get(&local_handler).copied() {
                parameters.extend(nextjs_handler_parameters(source, handler));
            }
            normalize_parameters(&mut parameters);
            let request_content_type = if parameters.iter().any(|value| value.location == "json") {
                Some("application/json".to_string())
            } else if parameters.iter().any(|value| value.location == "form") {
                Some("application/x-www-form-urlencoded".to_string())
            } else {
                None
            };
            routes.push(IndexedRoute {
                framework: "nextjs".to_string(),
                router_name: "app_router".to_string(),
                router_prefix: String::new(),
                http_method: method,
                path_template: path_template.clone(),
                handler_name: Some(local_handler),
                parameters,
                request_content_type,
                start_line: start.row + 1,
                end_line: end.row + 1,
            });
        }
    });
    routes
}
fn nextjs_app_route_path(relative_path: &str) -> Option<String> {
    let normalized = relative_path.replace('\\', "/");
    let app_tail = normalized
        .strip_prefix("app/")
        .or_else(|| normalized.strip_prefix("src/app/"))?;
    let mut parts: Vec<&str> = app_tail.split('/').collect();
    let filename = parts.pop()?;
    let route_file = matches!(
        filename,
        "route.ts" | "route.tsx" | "route.js" | "route.jsx" | "route.mjs" | "route.cjs"
    );
    if !route_file {
        return None;
    }

    let mut segments = Vec::new();
    for segment in parts {
        if segment.starts_with('(') && segment.ends_with(')') {
            continue;
        }
        if segment.starts_with('@') {
            continue;
        }
        if let Some(name) = segment
            .strip_prefix("[[...")
            .and_then(|value| value.strip_suffix("]]"))
        {
            let name = name.trim();
            if !is_identifier(name) {
                return None;
            }
            segments.push(format!("{{{name}}}"));
            continue;
        }
        if let Some(name) = segment
            .strip_prefix("[...")
            .and_then(|value| value.strip_suffix(']'))
        {
            let name = name.trim();
            if !is_identifier(name) {
                return None;
            }
            segments.push(format!("{{{name}}}"));
            continue;
        }
        if segment.starts_with('[') && segment.ends_with(']') && segment.len() > 2 {
            let name = segment[1..segment.len() - 1].trim();
            if !is_identifier(name) {
                return None;
            }
            segments.push(format!("{{{name}}}"));
            continue;
        }
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
        segments.push(segment.to_string());
    }

    Some(if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    })
}

fn nextjs_exported_http_handlers(value: &str) -> Vec<(String, String)> {
    const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut output = Vec::new();

    for method in METHODS {
        let function = format!("export function {method}(");
        let spaced_function = format!("export function {method} (");
        let async_function = format!("export async function {method}(");
        let spaced_async_function = format!("export async function {method} (");
        let const_handler = format!("export const {method} =");
        let let_handler = format!("export let {method} =");
        let var_handler = format!("export var {method} =");
        if normalized.contains(&function)
            || normalized.contains(&spaced_function)
            || normalized.contains(&async_function)
            || normalized.contains(&spaced_async_function)
            || normalized.contains(&const_handler)
            || normalized.contains(&let_handler)
            || normalized.contains(&var_handler)
        {
            output.push((method.to_string(), method.to_string()));
        }
    }

    if normalized.starts_with("export {") {
        if let Some(open) = normalized.find('{') {
            if let Some(relative_close) = normalized[open + 1..].find('}') {
                let body = &normalized[open + 1..open + 1 + relative_close];
                for item in body.split(',') {
                    let item = item.trim();
                    if item.is_empty() {
                        continue;
                    }
                    let (local, exported) = item
                        .rsplit_once(" as ")
                        .map(|(local, exported)| (local.trim(), exported.trim()))
                        .unwrap_or((item, item));
                    if !is_identifier(local) {
                        continue;
                    }
                    for method in METHODS {
                        if exported == method {
                            output.push((method.to_string(), local.to_string()));
                        }
                    }
                }
            }
        }
    }

    output.sort();
    output.dedup();
    output
}

fn nextjs_handler_inputs(
    relative_path: &str,
    source: &str,
    root: Node<'_>,
) -> Vec<IndexedHandlerInput> {
    if nextjs_app_route_path(relative_path).is_none() {
        return Vec::new();
    }
    let handlers = javascript_handlers(source, root);
    let mut names = Vec::new();
    walk(root, &mut |node| {
        if node.kind() != "export_statement" {
            return;
        }
        let Some(value) = text(source, node) else {
            return;
        };
        for (_, local) in nextjs_exported_http_handlers(value) {
            names.push(local);
        }
    });
    names.sort();
    names.dedup();

    let mut output = Vec::new();
    for name in names {
        let Some(handler) = handlers.get(&name).copied() else {
            continue;
        };
        let mut parameters = nextjs_handler_parameters(source, handler);
        normalize_parameters(&mut parameters);
        if parameters.is_empty() {
            continue;
        }
        let start = handler.start_position();
        let end = handler.end_position();
        output.push(IndexedHandlerInput {
            handler_name: name,
            parameters,
            start_line: start.row + 1,
            end_line: end.row + 1,
        });
    }
    output
}

fn nextjs_handler_parameters(source: &str, handler: Node<'_>) -> Vec<IndexedRouteParameter> {
    let mut parameters = express_handler_parameters(source, handler);
    let Some(request_name) = request_parameter_name(source, handler) else {
        return parameters;
    };
    let Some(function_text) = text(source, handler) else {
        return parameters;
    };

    for method in ["get", "getAll", "has"] {
        let marker = format!("{request_name}.nextUrl.searchParams.{method}(");
        for name in marker_quoted_arguments(function_text, &marker) {
            if !name.is_empty() && name.len() <= 256 {
                parameters.push(route_parameter(&name, "query"));
            }
        }
    }
    let header_marker = format!("{request_name}.headers.get(");
    for name in marker_quoted_arguments(function_text, &header_marker) {
        if !name.is_empty() && name.len() <= 256 {
            parameters.push(route_parameter(&name, "header"));
        }
    }

    let mut json_variables = Vec::new();
    let mut form_variables = Vec::new();
    let mut query_variables = Vec::new();
    let mut header_variables = Vec::new();
    walk(handler, &mut |node| {
        if node.kind() != "variable_declarator" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(value_node) = node.child_by_field_name("value") else {
            return;
        };
        let Some(value) = text(source, value_node).map(str::trim) else {
            return;
        };
        let name_text = text(source, name_node).map(str::trim).unwrap_or("");

        let json_marker = format!("{request_name}.json(");
        if value.contains(&json_marker) {
            if name_node.kind() == "identifier" && is_identifier(name_text) {
                json_variables.push(name_text.to_string());
            } else {
                for field in javascript_object_pattern_fields(name_text) {
                    parameters.push(route_parameter(&field, "json"));
                }
            }
        }

        let form_marker = format!("{request_name}.formData(");
        if value.contains(&form_marker) && name_node.kind() == "identifier" && is_identifier(name_text) {
            form_variables.push(name_text.to_string());
        }
        if value == format!("{request_name}.nextUrl.searchParams")
            && name_node.kind() == "identifier"
            && is_identifier(name_text)
        {
            query_variables.push(name_text.to_string());
        }
        if value == format!("{request_name}.headers")
            && name_node.kind() == "identifier"
            && is_identifier(name_text)
        {
            header_variables.push(name_text.to_string());
        }
    });

    walk(handler, &mut |node| {
        if node.kind() == "member_expression" {
            let Some(value) = text(source, node).map(str::trim) else {
                return;
            };
            if let Some((object, property)) = value.split_once('.') {
                if !property.contains('.')
                    && json_variables.iter().any(|candidate| candidate == object.trim())
                    && is_identifier(property.trim())
                {
                    parameters.push(route_parameter(property.trim(), "json"));
                }
            }
        }
        if node.kind() == "subscript_expression" {
            let Some(value) = text(source, node).map(str::trim) else {
                return;
            };
            for variable in &json_variables {
                let prefix = format!("{variable}[");
                if value.starts_with(&prefix) {
                    if let Some(name) = first_quoted_string(&value[prefix.len()..]) {
                        if !name.is_empty() && name.len() <= 256 {
                            parameters.push(route_parameter(&name, "json"));
                        }
                    }
                }
            }
        }
    });

    for variable in form_variables {
        for method in ["get", "getAll", "has"] {
            let marker = format!("{variable}.{method}(");
            for name in marker_quoted_arguments(function_text, &marker) {
                if !name.is_empty() && name.len() <= 256 {
                    parameters.push(route_parameter(&name, "form"));
                }
            }
        }
    }
    for variable in query_variables {
        for method in ["get", "getAll", "has"] {
            let marker = format!("{variable}.{method}(");
            for name in marker_quoted_arguments(function_text, &marker) {
                if !name.is_empty() && name.len() <= 256 {
                    parameters.push(route_parameter(&name, "query"));
                }
            }
        }
    }
    for variable in header_variables {
        let marker = format!("{variable}.get(");
        for name in marker_quoted_arguments(function_text, &marker) {
            if !name.is_empty() && name.len() <= 256 {
                parameters.push(route_parameter(&name, "header"));
            }
        }
    }
    parameters
}

fn javascript_object_pattern_fields(value: &str) -> Vec<String> {
    let value = value.trim();
    let Some(inner) = value.strip_prefix('{').and_then(|value| value.strip_suffix('}')) else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    for item in inner.split(',') {
        let item = item.trim();
        if item.is_empty() || item.starts_with("...") {
            continue;
        }
        let property = item
            .split_once(':')
            .map(|(property, _)| property)
            .unwrap_or(item);
        let property = property
            .split_once('=')
            .map(|(property, _)| property)
            .unwrap_or(property)
            .trim();
        let name = strip_quotes(property).unwrap_or_else(|| property.to_string());
        if is_identifier(&name) && name.len() <= 256 {
            fields.push(name);
        }
    }
    fields.sort();
    fields.dedup();
    fields
}
fn extract_express_routes(
    source: &str,
    root: Node<'_>,
) -> (Vec<IndexedRoute>, Vec<IndexedRouteMount>) {
    let handlers = javascript_handlers(source, root);
    let (prefixes, mounts) = express_mount_prefixes(source, root);
    let mut routes = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some((router, method)) = member_call(source, node) else {
            return;
        };
        if !HTTP_METHODS.contains(&method.as_str()) {
            return;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let Some(path_node) = arguments.named_child(0) else {
            return;
        };
        let Some(path) = static_string(source, path_node) else {
            return;
        };

        let handler_args: Vec<Node<'_>> = (1..arguments.named_child_count())
            .filter_map(|index| arguments.named_child(index))
            .collect();
        let handler_name = handler_args
            .last()
            .and_then(|value| handler_reference(source, *value));

        let router_prefix = prefixes.get(&router).cloned().unwrap_or_default();
        let full_path = combine_paths(
            (!router_prefix.is_empty()).then_some(router_prefix.as_str()),
            &path,
        );
        let mut parameters = path_parameters(&full_path);
        for handler_arg in &handler_args {
            let handler_node = if is_function_like(*handler_arg) {
                Some(*handler_arg)
            } else {
                handler_reference(source, *handler_arg)
                    .filter(|name| !name.contains('.'))
                    .and_then(|name| handlers.get(&name).copied())
            };
            if let Some(handler) = handler_node {
                parameters.extend(express_handler_parameters(source, handler));
            }
        }
        normalize_parameters(&mut parameters);

        let request_content_type = if parameters.iter().any(|value| value.location == "json") {
            Some("application/json".to_string())
        } else if parameters.iter().any(|value| value.location == "form") {
            Some("application/x-www-form-urlencoded".to_string())
        } else {
            None
        };
        let start = node.start_position();
        let end = node.end_position();
        routes.push(IndexedRoute {
            framework: "express".to_string(),
            router_name: router,
            router_prefix,
            http_method: method.to_ascii_uppercase(),
            path_template: full_path,
            handler_name,
            parameters,
            request_content_type,
            start_line: start.row + 1,
            end_line: end.row + 1,
        });
    });
    (routes, mounts)
}

fn javascript_handler_inputs(
    source: &str,
    root: Node<'_>,
) -> Vec<IndexedHandlerInput> {
    let mut output = Vec::new();
    for (handler_name, node) in javascript_handlers(source, root) {
        let mut parameters = express_handler_parameters(source, node);
        normalize_parameters(&mut parameters);
        if parameters.is_empty() {
            continue;
        }
        let start = node.start_position();
        let end = node.end_position();
        output.push(IndexedHandlerInput {
            handler_name,
            parameters,
            start_line: start.row + 1,
            end_line: end.row + 1,
        });
    }
    output
}

fn handler_reference(source: &str, node: Node<'_>) -> Option<String> {
    if node.kind() == "identifier" {
        return text(source, node).map(ToString::to_string);
    }
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    let object = text(source, object)?.trim();
    let property = text(source, property)?.trim();
    if is_identifier(object) && is_identifier(property) {
        Some(format!("{object}.{property}"))
    } else {
        None
    }
}

fn javascript_handlers<'a>(source: &str, root: Node<'a>) -> BTreeMap<String, Node<'a>> {
    let mut handlers = BTreeMap::new();
    walk(root, &mut |node| match node.kind() {
        "function_declaration" => {
            if let (Some(name), Some(_body)) = (
                node.child_by_field_name("name").and_then(|value| text(source, value)),
                node.child_by_field_name("body"),
            ) {
                handlers.insert(name.to_string(), node);
            }
        }
        "variable_declarator" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let Some(value_node) = node.child_by_field_name("value") else {
                return;
            };
            if name_node.kind() == "identifier" && is_function_like(value_node) {
                if let Some(name) = text(source, name_node) {
                    handlers.insert(name.to_string(), value_node);
                }
            }
        }
        _ => {}
    });
    handlers
}

fn express_mount_prefixes(
    source: &str,
    root: Node<'_>,
) -> (BTreeMap<String, String>, Vec<IndexedRouteMount>) {
    let mut prefixes = BTreeMap::<String, String>::new();
    let mut mounts = Vec::new();
    walk(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some((parent_router, method)) = member_call(source, node) else {
            return;
        };
        if method != "use" {
            return;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let Some(prefix_node) = arguments.named_child(0) else {
            return;
        };
        let Some(prefix) = static_string(source, prefix_node) else {
            return;
        };
        let Some(child_router) = arguments
            .named_child(1)
            .filter(|value| value.kind() == "identifier")
            .and_then(|value| text(source, value))
        else {
            return;
        };
        let start = node.start_position();
        let end = node.end_position();
        mounts.push(IndexedRouteMount {
            framework: "express".to_string(),
            parent_router,
            mounted_binding: child_router.to_string(),
            prefix: normalize_path(&prefix),
            prefix_mode: "prepend".to_string(),
            start_line: start.row + 1,
            end_line: end.row + 1,
        });
        prefixes
            .entry(child_router.to_string())
            .and_modify(|existing| {
                if prefix.len() > existing.len() {
                    *existing = normalize_path(&prefix);
                }
            })
            .or_insert_with(|| normalize_path(&prefix));
    });
    (prefixes, mounts)
}

fn express_handler_parameters(source: &str, handler: Node<'_>) -> Vec<IndexedRouteParameter> {
    let Some(request_name) = request_parameter_name(source, handler) else {
        return Vec::new();
    };
    let mut parameters = Vec::new();

    walk(handler, &mut |node| {
        if node.kind() == "member_expression" {
            if let Some(value) = text(source, node) {
                let parts: Vec<&str> = value.split('.').map(str::trim).collect();
                if parts.len() == 3 && parts[0] == request_name {
                    let location = match parts[1] {
                        "body" => Some("json"),
                        "query" => Some("query"),
                        "params" => Some("path"),
                        _ => None,
                    };
                    if let Some(location) = location {
                        if is_identifier(parts[2]) {
                            parameters.push(IndexedRouteParameter {
                                name: parts[2].to_string(),
                                location: location.to_string(),
                            });
                        }
                    }
                }
            }
        }
        if node.kind() == "variable_declarator" {
            let Some(value_node) = node.child_by_field_name("value") else {
                return;
            };
            let Some(value) = text(source, value_node) else {
                return;
            };
            let location = if value.trim() == format!("{request_name}.body") {
                Some("json")
            } else if value.trim() == format!("{request_name}.query") {
                Some("query")
            } else if value.trim() == format!("{request_name}.params") {
                Some("path")
            } else {
                None
            };
            let Some(location) = location else {
                return;
            };
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            collect_identifiers(source, name_node, &mut |name| {
                parameters.push(IndexedRouteParameter {
                    name: name.to_string(),
                    location: location.to_string(),
                });
            });
        }
    });

    parameters
}

fn request_parameter_name(source: &str, node: Node<'_>) -> Option<String> {
    if let Some(parameters) = node.child_by_field_name("parameters") {
        let mut first = None;
        collect_identifiers(source, parameters, &mut |name| {
            if first.is_none() {
                first = Some(name.to_string());
            }
        });
        if first.is_some() {
            return first;
        }
    }
    node.child_by_field_name("parameter")
        .and_then(|value| text(source, value))
        .map(str::trim)
        .filter(|value| is_identifier(value))
        .map(ToString::to_string)
}

fn extract_fastapi_routes(
    source: &str,
    root: Node<'_>,
) -> (Vec<IndexedRoute>, Vec<IndexedRouteMount>) {
    let model_fields = pydantic_model_fields(source, root);
    let (router_prefixes, mounts) = fastapi_router_prefixes(source, root);
    let mut routes = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "decorated_definition" {
            return;
        }
        let function = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "function_definition");
        let Some(function) = function else {
            return;
        };
        let handler_name = function
            .child_by_field_name("name")
            .and_then(|value| text(source, value))
            .map(ToString::to_string);

        for decorator in named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "decorator")
        {
            let Some(decorator_text) = text(source, decorator) else {
                continue;
            };
            let Some((router, method, path)) = parse_fastapi_decorator(decorator_text) else {
                continue;
            };
            let prefix = router_prefixes.get(&router).map(String::as_str);
            let router_prefix = prefix.unwrap_or("").to_string();
            let full_path = combine_paths(prefix, &path);
            let mut parameters = path_parameters(&full_path);
            parameters.extend(fastapi_function_parameters(
                source,
                function,
                &full_path,
                &model_fields,
            ));
            normalize_parameters(&mut parameters);
            let request_content_type = if parameters.iter().any(|value| value.location == "json") {
                Some("application/json".to_string())
            } else if parameters.iter().any(|value| value.location == "form") {
                Some("application/x-www-form-urlencoded".to_string())
            } else {
                None
            };
            let start = decorator.start_position();
            let end = function.end_position();
            routes.push(IndexedRoute {
                framework: "fastapi".to_string(),
                router_name: router,
                router_prefix,
                http_method: method.to_ascii_uppercase(),
                path_template: full_path,
                handler_name: handler_name.clone(),
                parameters,
                request_content_type,
                start_line: start.row + 1,
                end_line: end.row + 1,
            });
        }
    });

    (routes, mounts)
}

fn extract_flask_routes(
    source: &str,
    root: Node<'_>,
) -> (
    Vec<IndexedRoute>,
    Vec<IndexedRouteMount>,
    Vec<IndexedHandlerInput>,
) {
    let (prefixes, mounts) = flask_router_prefixes(source, root);
    if prefixes.is_empty() {
        return (Vec::new(), mounts, Vec::new());
    }
    let mut routes = Vec::new();
    let mut handler_inputs = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "decorated_definition" {
            return;
        }
        let Some(function) = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "function_definition")
        else {
            return;
        };
        let handler_name = function
            .child_by_field_name("name")
            .and_then(|value| text(source, value))
            .map(ToString::to_string);
        let mut handler_parameters = flask_handler_parameters(source, function);
        normalize_parameters(&mut handler_parameters);
        let mut matched_route = false;

        for decorator in named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "decorator")
        {
            let Some(raw) = text(source, decorator) else {
                continue;
            };
            let Some((router, methods, path)) = parse_flask_decorator(raw, &prefixes) else {
                continue;
            };
            matched_route = true;
            let router_prefix = prefixes.get(&router).cloned().unwrap_or_default();
            let full_path = combine_paths(
                (!router_prefix.is_empty()).then_some(router_prefix.as_str()),
                &path,
            );
            let mut parameters = path_parameters(&full_path);
            parameters.extend(handler_parameters.iter().cloned());
            normalize_parameters(&mut parameters);
            let request_content_type = if parameters.iter().any(|value| value.location == "json") {
                Some("application/json".to_string())
            } else if parameters.iter().any(|value| value.location == "form") {
                Some("application/x-www-form-urlencoded".to_string())
            } else {
                None
            };
            let start = decorator.start_position();
            let end = function.end_position();
            for method in methods {
                routes.push(IndexedRoute {
                    framework: "flask".to_string(),
                    router_name: router.clone(),
                    router_prefix: router_prefix.clone(),
                    http_method: method,
                    path_template: full_path.clone(),
                    handler_name: handler_name.clone(),
                    parameters: parameters.clone(),
                    request_content_type: request_content_type.clone(),
                    start_line: start.row + 1,
                    end_line: end.row + 1,
                });
            }
        }

        if matched_route && !handler_parameters.is_empty() {
            if let Some(handler_name) = handler_name {
                let start = function.start_position();
                let end = function.end_position();
                handler_inputs.push(IndexedHandlerInput {
                    handler_name,
                    parameters: handler_parameters,
                    start_line: start.row + 1,
                    end_line: end.row + 1,
                });
            }
        }
    });

    (routes, mounts, handler_inputs)
}

fn flask_handler_parameters(source: &str, function: Node<'_>) -> Vec<IndexedRouteParameter> {
    let Some(function_text) = text(source, function) else {
        return Vec::new();
    };
    let mut parameters = Vec::new();

    for (collection, location) in [
        ("request.args", "query"),
        ("request.form", "form"),
        ("request.headers", "header"),
        ("request.cookies", "cookie"),
        ("request.json", "json"),
    ] {
        for method in ["get", "getlist"] {
            let marker = format!("{collection}.{method}(");
            for name in marker_quoted_arguments(function_text, &marker) {
                if !name.is_empty() && name.len() <= 256 {
                    parameters.push(route_parameter(&name, location));
                }
            }
        }
        let marker = format!("{collection}[");
        for name in marker_quoted_subscripts(function_text, &marker) {
            if !name.is_empty() && name.len() <= 256 {
                parameters.push(route_parameter(&name, location));
            }
        }
    }

    for method in ["get", "getlist"] {
        let marker = format!("request.get_json().{method}(");
        for name in marker_quoted_arguments(function_text, &marker) {
            if !name.is_empty() && name.len() <= 256 {
                parameters.push(route_parameter(&name, "json"));
            }
        }
    }
    for name in marker_quoted_subscripts(function_text, "request.get_json()[") {
        if !name.is_empty() && name.len() <= 256 {
            parameters.push(route_parameter(&name, "json"));
        }
    }

    let mut aliases = BTreeMap::<String, String>::new();
    walk(function, &mut |node| {
        if node.kind() != "assignment" {
            return;
        }
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        let Some(name) = text(source, left).map(str::trim) else {
            return;
        };
        if !is_identifier(name) {
            return;
        }
        let Some(value) = text(source, right).map(str::trim) else {
            return;
        };
        let location = match value {
            "request.args" => Some("query"),
            "request.form" => Some("form"),
            "request.headers" => Some("header"),
            "request.cookies" => Some("cookie"),
            "request.json" => Some("json"),
            _ if value.starts_with("request.get_json(") => Some("json"),
            _ => None,
        };
        if let Some(location) = location {
            aliases.insert(name.to_string(), location.to_string());
        }
    });

    for (alias, location) in aliases {
        for method in ["get", "getlist"] {
            let marker = format!("{alias}.{method}(");
            for name in marker_quoted_arguments(function_text, &marker) {
                if !name.is_empty() && name.len() <= 256 {
                    parameters.push(route_parameter(&name, &location));
                }
            }
        }
        let marker = format!("{alias}[");
        for name in marker_quoted_subscripts(function_text, &marker) {
            if !name.is_empty() && name.len() <= 256 {
                parameters.push(route_parameter(&name, &location));
            }
        }
    }

    parameters
}

fn marker_quoted_subscripts(value: &str, marker: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = value[offset..].find(marker) {
        let start = offset + relative + marker.len();
        let tail = value[start..].trim_start();
        let Some(quote) = tail.chars().next().filter(|value| matches!(value, '"' | '\'')) else {
            offset = start;
            continue;
        };
        let quoted = &tail[quote.len_utf8()..];
        if let Some(end) = quoted.find(quote) {
            let remainder = quoted[end + quote.len_utf8()..].trim_start();
            if remainder.starts_with(']') {
                output.push(quoted[..end].to_string());
            }
        }
        offset = start;
    }
    output
}
fn flask_router_prefixes(
    source: &str,
    root: Node<'_>,
) -> (BTreeMap<String, String>, Vec<IndexedRouteMount>) {
    let mut prefixes = BTreeMap::new();
    let mut mounts = Vec::new();

    walk(root, &mut |node| {
        if node.kind() == "assignment" {
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return;
            };
            let Some(name) = text(source, left).map(str::trim) else {
                return;
            };
            let Some(value) = text(source, right) else {
                return;
            };
            if !is_identifier(name) {
                return;
            }
            if value.contains("Flask(") {
                prefixes.insert(name.to_string(), "/".to_string());
            } else if value.contains("Blueprint(") {
                let prefix = keyword_string(value, "url_prefix")
                    .map(|value| normalize_path(&value))
                    .unwrap_or_else(|| "/".to_string());
                prefixes.insert(name.to_string(), prefix);
            }
        }

        if !node.kind().contains("call") {
            return;
        }
        let Some(value) = text(source, node) else {
            return;
        };
        let Some(open) = value.find(".register_blueprint(") else {
            return;
        };
        let parent_router = value[..open].trim();
        if !is_identifier(parent_router) {
            return;
        }
        let tail = &value[open + ".register_blueprint(".len()..];
        let child = tail
            .split([',', ')'])
            .next()
            .map(str::trim)
            .filter(|candidate| is_identifier(candidate));
        let Some(child) = child else {
            return;
        };
        let explicit_prefix = keyword_string(value, "url_prefix")
            .map(|value| normalize_path(&value));
        if let Some(prefix) = explicit_prefix.as_ref() {
            if prefixes.contains_key(child) {
                prefixes.insert(child.to_string(), prefix.clone());
            }
        }
        let prefix_mode = if explicit_prefix.is_some() {
            "override_router_prefix"
        } else {
            "prepend"
        };
        let prefix = explicit_prefix.unwrap_or_else(|| "/".to_string());
        let start = node.start_position();
        let end = node.end_position();
        mounts.push(IndexedRouteMount {
            framework: "flask".to_string(),
            parent_router: parent_router.to_string(),
            mounted_binding: child.to_string(),
            prefix,
            prefix_mode: prefix_mode.to_string(),
            start_line: start.row + 1,
            end_line: end.row + 1,
        });
    });

    (prefixes, mounts)
}

fn parse_flask_decorator(
    value: &str,
    routers: &BTreeMap<String, String>,
) -> Option<(String, Vec<String>, String)> {
    let trimmed = value.trim().trim_start_matches('@');
    let open = trimmed.find('(')?;
    let member = trimmed[..open].trim();
    let (router, method) = member.rsplit_once('.')?;
    if !is_identifier(router) || !routers.contains_key(router) {
        return None;
    }
    let path = first_quoted_string(&trimmed[open + 1..])?;
    if method == "route" {
        let methods = keyword_quoted_strings(trimmed, "methods");
        let methods = if methods.is_empty() {
            vec!["GET".to_string()]
        } else {
            methods
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .filter(|method| HTTP_METHODS.iter().any(|known| known.eq_ignore_ascii_case(method)))
                .collect()
        };
        if methods.is_empty() {
            return None;
        }
        return Some((router.to_string(), methods, path));
    }
    if HTTP_METHODS.contains(&method.to_ascii_lowercase().as_str()) {
        return Some((
            router.to_string(),
            vec![method.to_ascii_uppercase()],
            path,
        ));
    }
    None
}

fn extract_laravel_routes(
    source: &str,
    root: Node<'_>,
) -> (Vec<IndexedRoute>, Vec<IndexedRouteMount>) {
    let mut routes = Vec::new();
    walk(root, &mut |node| {
        if !node.kind().contains("call") {
            return;
        }
        let Some(value) = text(source, node).map(str::trim) else {
            return;
        };
        let Some(tail) = value.strip_prefix("Route::") else {
            return;
        };
        let Some(open) = tail.find('(') else {
            return;
        };
        let method = tail[..open].trim().to_ascii_lowercase();
        let Some(path) = first_quoted_string(&tail[open + 1..]) else {
            return;
        };
        let group_prefix = laravel_ancestor_prefix(source, node);
        let start = node.start_position();
        let end = node.end_position();

        if matches!(method.as_str(), "resource" | "apiresource") {
            let base = combine_paths(group_prefix.as_deref(), &path);
            let Some(parameter) = laravel_resource_parameter(&base) else {
                return;
            };
            let member = format!("{base}/{{{parameter}}}");
            let mut expanded = vec![
                ("GET", base.clone()),
                ("POST", base.clone()),
                ("GET", member.clone()),
                ("PUT", member.clone()),
                ("PATCH", member.clone()),
                ("DELETE", member.clone()),
            ];
            if method == "resource" {
                expanded.push(("GET", format!("{base}/create")));
                expanded.push(("GET", format!("{member}/edit")));
            }
            for (http_method, resource_path) in expanded {
                push_laravel_indexed_route(
                    &mut routes,
                    http_method,
                    resource_path,
                    group_prefix.as_deref(),
                    start.row + 1,
                    end.row + 1,
                );
            }
            return;
        }

        if !HTTP_METHODS.contains(&method.as_str()) {
            return;
        }
        let full_path = combine_paths(group_prefix.as_deref(), &path);
        push_laravel_indexed_route(
            &mut routes,
            &method.to_ascii_uppercase(),
            full_path,
            group_prefix.as_deref(),
            start.row + 1,
            end.row + 1,
        );
    });
    (routes, Vec::new())
}

fn push_laravel_indexed_route(
    routes: &mut Vec<IndexedRoute>,
    method: &str,
    path_template: String,
    router_prefix: Option<&str>,
    start_line: usize,
    end_line: usize,
) {
    let mut parameters = path_parameters(&path_template);
    normalize_parameters(&mut parameters);
    routes.push(IndexedRoute {
        framework: "laravel".to_string(),
        router_name: "Route".to_string(),
        router_prefix: router_prefix.unwrap_or("").to_string(),
        http_method: method.to_ascii_uppercase(),
        path_template,
        handler_name: None,
        parameters,
        request_content_type: None,
        start_line,
        end_line,
    });
}

fn laravel_resource_parameter(path: &str) -> Option<String> {
    let segment = path
        .trim_matches('/')
        .rsplit('/')
        .next()?
        .trim();
    if segment.is_empty() || segment.starts_with('{') {
        return None;
    }
    let mut name = segment.replace('-', "_");
    if let Some(stem) = name.strip_suffix("ies") {
        name = format!("{stem}y");
    } else if name.ends_with('s') && name.len() > 1 {
        name.pop();
    }
    if is_identifier(&name) {
        Some(name)
    } else {
        None
    }
}

fn laravel_ancestor_prefix(source: &str, node: Node<'_>) -> Option<String> {
    let mut prefixes = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        let Some(value) = text(source, parent) else {
            current = parent.parent();
            continue;
        };
        if parent.kind().contains("call")
            && (value.contains("->group(") || value.contains("Route::group("))
        {
            if let Some(prefix) = laravel_chain_prefix(value) {
                prefixes.push(prefix);
            }
        }
        current = parent.parent();
    }
    if prefixes.is_empty() {
        return None;
    }
    prefixes.reverse();
    let mut combined = String::new();
    for prefix in prefixes {
        let next = if combined.is_empty() {
            combine_paths(None, &prefix)
        } else {
            combine_paths(Some(combined.as_str()), &prefix)
        };
        combined = next;
    }
    Some(combined)
}

fn laravel_chain_prefix(value: &str) -> Option<String> {
    if let Some(index) = value.find("->prefix(") {
        return first_quoted_string(&value[index + "->prefix(".len()..])
            .map(|prefix| normalize_path(&prefix));
    }
    if value.contains("Route::group(") {
        let compact = value.split_whitespace().collect::<String>();
        for quote in ['\'', '"'] {
            let marker = format!("{quote}prefix{quote}=>{quote}");
            if let Some(index) = compact.find(&marker) {
                let tail = &compact[index + marker.len()..];
                let end = tail.find(quote)?;
                return Some(normalize_path(&tail[..end]));
            }
        }
    }
    None
}

fn extract_go_routes(
    source: &str,
    root: Node<'_>,
) -> (
    Vec<IndexedRoute>,
    Vec<IndexedRouteMount>,
    Vec<IndexedHandlerInput>,
) {
    let Some(framework) = detect_go_route_framework(source) else {
        return (Vec::new(), Vec::new(), Vec::new());
    };

    let handlers = go_handlers(source, root);
    let json_models = go_json_models(source, root);
    let handler_inputs = go_handler_inputs(source, &handlers, framework, &json_models);
    let handler_parameters: BTreeMap<String, Vec<IndexedRouteParameter>> = handler_inputs
        .iter()
        .map(|input| (input.handler_name.clone(), input.parameters.clone()))
        .collect();
    let (prefixes, mounts) = go_group_prefixes(source, root, framework);
    let mut routes = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(value) = text(source, node).map(str::trim) else {
            return;
        };
        let Some(open) = value.find('(') else {
            return;
        };
        let callee = value[..open].trim();
        let Some((router, method_raw)) = callee.rsplit_once('.') else {
            return;
        };
        let router = router.trim();
        if !is_identifier(router) {
            return;
        }

        let method_lower = method_raw.trim().to_ascii_lowercase();
        let quoted = quoted_strings(&value[open + 1..]);
        let (http_method, path) = if framework == "go-stdlib" {
            if !matches!(method_lower.as_str(), "handle" | "handlefunc") {
                return;
            }
            let Some(pattern) = quoted.first() else {
                return;
            };
            let Some((method, path)) = parse_go_stdlib_method_pattern(pattern) else {
                return;
            };
            (method, path)
        } else if HTTP_METHODS.contains(&method_lower.as_str()) {
            let Some(path) = quoted.first() else {
                return;
            };
            (method_lower.to_ascii_uppercase(), path.clone())
        } else if matches!(method_lower.as_str(), "handle" | "add") {
            if quoted.len() < 2 {
                return;
            }
            let candidate = quoted[0].to_ascii_lowercase();
            if !HTTP_METHODS.contains(&candidate.as_str()) {
                return;
            }
            (candidate.to_ascii_uppercase(), quoted[1].clone())
        } else {
            return;
        };

        let handler_name = go_route_handler_reference(value);
        let full_path = combine_paths(prefixes.get(router).map(String::as_str), &path);
        let mut parameters = path_parameters(&full_path);
        if let Some(name) = handler_name.as_ref() {
            if let Some(handler) = handler_parameters.get(name) {
                parameters.extend(handler.iter().cloned());
            }
        }
        normalize_parameters(&mut parameters);
        let request_content_type = if parameters.iter().any(|value| value.location == "json") {
            Some("application/json".to_string())
        } else if parameters.iter().any(|value| value.location == "form") {
            Some("application/x-www-form-urlencoded".to_string())
        } else {
            None
        };
        let start = node.start_position();
        let end = node.end_position();
        routes.push(IndexedRoute {
            framework: framework.to_string(),
            router_name: router.to_string(),
            http_method,
            path_template: full_path,
            handler_name,
            parameters,
            request_content_type,
            start_line: start.row + 1,
            end_line: end.row + 1,
        });
    });

    (routes, mounts, handler_inputs)
}

fn go_handlers<'a>(source: &str, root: Node<'a>) -> BTreeMap<String, Node<'a>> {
    let mut handlers = BTreeMap::new();
    walk(root, &mut |node| {
        if node.kind() != "function_declaration" {
            return;
        }
        let Some(name) = node
            .child_by_field_name("name")
            .and_then(|value| text(source, value))
            .map(str::trim)
        else {
            return;
        };
        if is_identifier(name) {
            handlers.insert(name.to_string(), node);
        }
    });
    handlers
}

fn go_handler_inputs(
    source: &str,
    handlers: &BTreeMap<String, Node<'_>>,
    framework: &str,
    json_models: &BTreeMap<String, Vec<String>>,
) -> Vec<IndexedHandlerInput> {
    let mut output = Vec::new();
    for (name, node) in handlers {
        let Some(body) = text(source, *node) else {
            continue;
        };
        let mut parameters = go_handler_parameters(body, framework, json_models);
        normalize_parameters(&mut parameters);
        if parameters.is_empty() {
            continue;
        }
        let start = node.start_position();
        let end = node.end_position();
        output.push(IndexedHandlerInput {
            handler_name: name.clone(),
            parameters,
            start_line: start.row + 1,
            end_line: end.row + 1,
        });
    }
    output
}

fn go_handler_parameters(
    body: &str,
    framework: &str,
    json_models: &BTreeMap<String, Vec<String>>,
) -> Vec<IndexedRouteParameter> {
    let mut parameters = Vec::new();
    let mut collect = |markers: &[&str], location: &str| {
        for marker in markers {
            for name in marker_quoted_arguments(body, marker) {
                if !name.is_empty() && name.len() <= 256 {
                    parameters.push(route_parameter(&name, location));
                }
            }
        }
    };

    match framework {
        "gin" => {
            collect(&[".Query(", ".DefaultQuery("], "query");
            collect(&[".Param("], "path");
            collect(&[".PostForm(", ".DefaultPostForm("], "form");
            collect(&[".GetHeader("], "header");
        }
        "echo" => {
            collect(&[".QueryParam("], "query");
            collect(&[".Param("], "path");
            collect(&[".FormValue("], "form");
            collect(&[".Header.Get("], "header");
        }
        "chi" => {
            collect(&["chi.URLParam("], "path");
            collect(&[".URL.Query().Get("], "query");
            collect(&[".FormValue("], "form");
            collect(&[".Header.Get("], "header");
        }
        "go-stdlib" => {
            collect(&[".PathValue("], "path");
            collect(&[".URL.Query().Get("], "query");
            collect(&[".FormValue("], "form");
            collect(&[".Header.Get("], "header");
        }
        _ => {}
    }

    if let Some(model) = go_explicit_json_binding_model(body) {
        if let Some(fields) = json_models.get(&model) {
            for field in fields {
                parameters.push(route_parameter(field, "json"));
            }
        }
    }
    parameters
}

fn go_json_models(source: &str, root: Node<'_>) -> BTreeMap<String, Vec<String>> {
    let mut models = BTreeMap::new();
    walk(root, &mut |node| {
        if node.kind() != "type_spec" {
            return;
        }
        let Some(name) = node
            .child_by_field_name("name")
            .and_then(|value| text(source, value))
            .map(str::trim)
        else {
            return;
        };
        if !is_identifier(name) {
            return;
        }
        let Some(raw) = text(source, node) else {
            return;
        };
        if !raw.contains("struct") || !raw.contains('{') {
            return;
        }
        let fields = go_struct_json_fields(raw);
        if !fields.is_empty() {
            models.insert(name.to_string(), fields);
        }
    });
    models
}

fn go_struct_json_fields(raw: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let Some(open) = raw.find('{') else {
        return fields;
    };
    let Some(close) = raw.rfind('}') else {
        return fields;
    };
    if close <= open {
        return fields;
    }

    for line in raw[open + 1..close].lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('}') {
            continue;
        }

        let declaration = line.split('`').next().unwrap_or(line).trim();
        let mut tokens = declaration.split_whitespace();
        let Some(field_name) = tokens.next() else {
            continue;
        };
        if tokens.next().is_none()
            || !is_identifier(field_name)
            || !field_name
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_uppercase())
        {
            continue;
        }

        let json_name = go_json_tag_name(line).unwrap_or_else(|| field_name.to_string());
        if json_name == "-" || json_name.is_empty() || json_name.len() > 256 {
            continue;
        }
        fields.push(json_name);
    }

    fields.sort();
    fields.dedup();
    fields.truncate(256);
    fields
}

fn go_json_tag_name(line: &str) -> Option<String> {
    let marker = r#"json:""#;
    let index = line.find(marker)?;
    let tail = &line[index + marker.len()..];
    let end = tail.find('"')?;
    let tag = &tail[..end];
    let name = tag.split(',').next().unwrap_or("").trim();
    if name == "-" {
        return Some("-".to_string());
    }
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn go_explicit_json_binding_model(body: &str) -> Option<String> {
    let variables = go_handler_local_types(body);
    for marker in [".ShouldBindJSON(", ".BindJSON("] {
        if let Some(variable) = go_bound_variable(body, marker) {
            if let Some(model) = variables.get(&variable) {
                return Some(model.clone());
            }
        }
    }

    if body.contains("json.NewDecoder") {
        if let Some(variable) = go_bound_variable(body, ".Decode(") {
            if let Some(model) = variables.get(&variable) {
                return Some(model.clone());
            }
        }
    }
    None
}

fn go_handler_local_types(body: &str) -> BTreeMap<String, String> {
    let mut variables = BTreeMap::new();
    for line in body.lines() {
        let trimmed = line.trim().trim_end_matches(';').trim();

        if let Some(rest) = trimmed.strip_prefix("var ") {
            let mut parts = rest.split_whitespace();
            let Some(variable) = parts.next() else {
                continue;
            };
            let Some(model) = parts.next() else {
                continue;
            };
            let model = model.trim_start_matches('*').trim();
            if is_identifier(variable) && is_identifier(model) {
                variables.insert(variable.to_string(), model.to_string());
            }
            continue;
        }

        let Some((left, right)) = trimmed.split_once(":=") else {
            continue;
        };
        let variable = left.trim();
        if !is_identifier(variable) {
            continue;
        }
        let right = right.trim().trim_start_matches('&');
        let model = if let Some(tail) = right.strip_prefix("new(") {
            tail.split(')').next().unwrap_or("").trim()
        } else {
            right.split(['{', '(']).next().unwrap_or("").trim()
        };
        if is_identifier(model) {
            variables.insert(variable.to_string(), model.to_string());
        }
    }
    variables
}

fn go_bound_variable(body: &str, marker: &str) -> Option<String> {
    let index = body.find(marker)?;
    let tail = &body[index + marker.len()..];
    let argument = tail
        .split([',', ')'])
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('&')
        .trim();
    if is_identifier(argument) {
        Some(argument.to_string())
    } else {
        None
    }
}

fn marker_quoted_arguments(value: &str, marker: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = value[offset..].find(marker) {
        let start = offset + relative + marker.len();
        let tail = &value[start..];
        let arguments = bounded_call_arguments(tail);
        if let Some(argument) = first_quoted_string(arguments) {
            output.push(argument);
        }
        offset = start;
        if offset >= value.len() {
            break;
        }
    }
    output
}

fn bounded_call_arguments(value: &str) -> &str {
    let mut nested = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if character == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(character, '"' | '\'' | '`') {
            quote = Some(character);
            continue;
        }
        match character {
            '(' => nested += 1,
            ')' if nested == 0 => return &value[..index],
            ')' => nested = nested.saturating_sub(1),
            _ => {}
        }
    }
    value
}

fn go_route_handler_reference(value: &str) -> Option<String> {
    let close = value.rfind(')')?;
    let open = value.find('(')?;
    if close <= open {
        return None;
    }
    let arguments = &value[open + 1..close];
    let candidate = arguments.rsplit(',').next()?.trim();
    if is_identifier(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn detect_go_route_framework(source: &str) -> Option<&'static str> {
    if source.contains("github.com/gin-gonic/gin") {
        return Some("gin");
    }
    if source.contains("github.com/labstack/echo") {
        return Some("echo");
    }
    if source.contains("github.com/go-chi/chi") {
        return Some("chi");
    }
    if source.contains("\"net/http\"") {
        return Some("go-stdlib");
    }
    None
}

fn parse_go_stdlib_method_pattern(pattern: &str) -> Option<(String, String)> {
    let trimmed = pattern.trim();
    let split = trimmed.find(char::is_whitespace)?;
    let method = trimmed[..split].trim().to_ascii_lowercase();
    if !HTTP_METHODS.contains(&method.as_str()) {
        return None;
    }
    let path = trimmed[split..].trim();
    if !path.starts_with('/') || path.contains(char::is_whitespace) {
        return None;
    }
    Some((method.to_ascii_uppercase(), path.to_string()))
}

fn go_group_prefixes(
    source: &str,
    root: Node<'_>,
    framework: &str,
) -> (BTreeMap<String, String>, Vec<IndexedRouteMount>) {
    let mut declarations = Vec::<(String, String, String, usize, usize)>::new();
    walk(root, &mut |node| {
        if !matches!(node.kind(), "short_var_declaration" | "var_declaration") {
            return;
        }
        let Some(value) = text(source, node).map(str::trim) else {
            return;
        };
        let Some(group_index) = value.find(".Group(") else {
            return;
        };
        let left = value
            .split_once(":=")
            .or_else(|| value.split_once('='))
            .map(|(left, _)| left.trim())
            .unwrap_or("");
        if !is_identifier(left) {
            return;
        }
        let parent = value[..group_index]
            .rsplit_once(['=', ' '])
            .map(|(_, tail)| tail.trim())
            .unwrap_or(&value[..group_index])
            .trim();
        if !is_identifier(parent) {
            return;
        }
        let Some(prefix) = first_quoted_string(&value[group_index + ".Group(".len()..]) else {
            return;
        };
        let start = node.start_position();
        let end = node.end_position();
        declarations.push((
            left.to_string(),
            parent.to_string(),
            normalize_path(&prefix),
            start.row + 1,
            end.row + 1,
        ));
    });

    let mut prefixes = BTreeMap::new();
    let mut mounts = Vec::new();
    for _ in 0..declarations.len().max(1) {
        let mut changed = false;
        for (child, parent, prefix, start_line, end_line) in &declarations {
            let effective = combine_paths(prefixes.get(parent).map(String::as_str), prefix);
            if prefixes.get(child) != Some(&effective) {
                prefixes.insert(child.clone(), effective.clone());
                changed = true;
            }
            mounts.push(IndexedRouteMount {
                framework: framework.to_string(),
                parent_router: parent.clone(),
                mounted_binding: child.clone(),
                prefix: prefix.clone(),
                start_line: *start_line,
                end_line: *end_line,
            });
        }
        if !changed {
            break;
        }
    }
    mounts.sort_by(|left, right| {
        (
            &left.parent_router,
            &left.mounted_binding,
            &left.prefix,
            left.start_line,
        )
            .cmp(&(
                &right.parent_router,
                &right.mounted_binding,
                &right.prefix,
                right.start_line,
            ))
    });
    mounts.dedup_by(|left, right| {
        left.framework == right.framework
            && left.parent_router == right.parent_router
            && left.mounted_binding == right.mounted_binding
            && left.prefix == right.prefix
            && left.start_line == right.start_line
    });

    (prefixes, mounts)
}

fn extract_rust_routes(
    source: &str,
    root: Node<'_>,
) -> (Vec<IndexedRoute>, Vec<IndexedHandlerInput>) {
    let handlers = rust_handlers(source, root);
    let models = rust_struct_models(source, root);
    let handler_inputs = rust_handler_inputs(source, &handlers, &models);
    let handler_parameters: BTreeMap<String, Vec<IndexedRouteParameter>> = handler_inputs
        .iter()
        .map(|input| (input.handler_name.clone(), input.parameters.clone()))
        .collect();
    let mut routes = Vec::new();

    let attribute_framework = if source.contains("actix_web") {
        Some("actix-web")
    } else if source.contains("rocket") {
        Some("rocket")
    } else {
        None
    };
    if let Some(framework) = attribute_framework {
        routes.extend(extract_rust_attribute_routes(
            source,
            framework,
            &handler_parameters,
        ));
    }

    if source.contains("axum") {
        walk(root, &mut |node| {
            if node.kind() != "call_expression" {
                return;
            }
            let Some(value) = text(source, node).map(str::trim) else {
                return;
            };
            let Some(route_index) = value.rfind(".route(") else {
                return;
            };
            let tail = &value[route_index + ".route(".len()..];
            let Some(path) = first_quoted_string(tail) else {
                return;
            };
            let methods = axum_methods(tail);
            if methods.is_empty() {
                return;
            }
            let handlers_by_method = axum_method_handlers(tail);
            let full_path = normalize_path(&path);
            let start = node.start_position();
            let end = node.end_position();
            for method in methods {
                let handler_name = handlers_by_method.get(&method).cloned();
                let mut parameters = path_parameters(&full_path);
                if let Some(name) = handler_name.as_ref() {
                    if let Some(handler) = handler_parameters.get(name) {
                        parameters.extend(handler.iter().cloned());
                    }
                }
                normalize_parameters(&mut parameters);
                routes.push(IndexedRoute {
                    framework: "axum".to_string(),
                    router_name: "Router".to_string(),
                    http_method: method,
                    path_template: full_path.clone(),
                    handler_name,
                    request_content_type: rust_request_content_type(&parameters),
                    parameters,
                    start_line: start.row + 1,
                    end_line: end.row + 1,
                });
            }
        });
    }

    (routes, handler_inputs)
}

fn extract_rust_attribute_routes(
    source: &str,
    framework: &str,
    handler_parameters: &BTreeMap<String, Vec<IndexedRouteParameter>>,
) -> Vec<IndexedRoute> {
    let mut routes = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("#[") {
            continue;
        }
        let inner = trimmed.trim_start_matches("#[").trim_end_matches(']').trim();
        let Some(open) = inner.find('(') else {
            continue;
        };
        let method = inner[..open].trim().to_ascii_lowercase();
        if !HTTP_METHODS.contains(&method.as_str()) {
            continue;
        }
        let Some(raw_path) = first_quoted_string(&inner[open + 1..]) else {
            continue;
        };
        let (full_path, mut parameters) = rust_attribute_path_and_query(framework, &raw_path);
        let handler_name = rust_following_function_name(&lines, index);
        if let Some(name) = handler_name.as_ref() {
            if let Some(handler) = handler_parameters.get(name) {
                parameters.extend(handler.iter().cloned());
            }
        }
        normalize_parameters(&mut parameters);
        routes.push(IndexedRoute {
            framework: framework.to_string(),
            router_name: "attribute".to_string(),
            http_method: method.to_ascii_uppercase(),
            path_template: full_path,
            handler_name,
            request_content_type: rust_request_content_type(&parameters),
            parameters,
            start_line: index + 1,
            end_line: index + 1,
        });
    }
    routes
}

fn rust_attribute_path_and_query(
    framework: &str,
    raw_path: &str,
) -> (String, Vec<IndexedRouteParameter>) {
    let mut parameters = Vec::new();
    let path = if framework == "rocket" {
        if let Some((path, query)) = raw_path.split_once('?') {
            for segment in query.split('&') {
                let segment = segment.trim();
                if segment.starts_with('<') && segment.ends_with('>') && segment.len() > 2 {
                    let name = segment[1..segment.len() - 1].trim_end_matches("..").trim();
                    if is_identifier(name) {
                        parameters.push(route_parameter(name, "query"));
                    }
                }
            }
            path
        } else {
            raw_path
        }
    } else {
        raw_path
    };
    let full_path = normalize_path(path);
    parameters.extend(path_parameters(&full_path));
    (full_path, parameters)
}

fn rust_following_function_name(lines: &[&str], attribute_index: usize) -> Option<String> {
    let end = lines.len().min(attribute_index.saturating_add(12));
    for line in &lines[attribute_index + 1..end] {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[") {
            continue;
        }
        let Some(index) = trimmed.find("fn ") else {
            continue;
        };
        let tail = &trimmed[index + 3..];
        let name = tail
            .split(|character: char| character == '(' || character.is_whitespace())
            .next()
            .unwrap_or("")
            .trim();
        if is_identifier(name) {
            return Some(name.to_string());
        }
    }
    None
}

fn rust_handlers<'a>(source: &str, root: Node<'a>) -> BTreeMap<String, Node<'a>> {
    let mut handlers = BTreeMap::new();
    walk(root, &mut |node| {
        if node.kind() != "function_item" {
            return;
        }
        let Some(name) = node
            .child_by_field_name("name")
            .and_then(|value| text(source, value))
            .map(str::trim)
        else {
            return;
        };
        if is_identifier(name) {
            handlers.insert(name.to_string(), node);
        }
    });
    handlers
}

fn rust_struct_models(source: &str, root: Node<'_>) -> BTreeMap<String, Vec<String>> {
    let mut models = BTreeMap::new();
    walk(root, &mut |node| {
        if node.kind() != "struct_item" {
            return;
        }
        let Some(name) = node
            .child_by_field_name("name")
            .and_then(|value| text(source, value))
            .map(str::trim)
        else {
            return;
        };
        let Some(raw) = text(source, node) else {
            return;
        };
        if !raw.contains('{') {
            return;
        }
        let fields = rust_struct_fields(raw);
        if !fields.is_empty() {
            models.insert(name.to_string(), fields);
        }
    });
    models
}

fn rust_struct_fields(raw: &str) -> Vec<String> {
    let Some(open) = raw.find('{') else {
        return Vec::new();
    };
    let Some(close) = raw.rfind('}') else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }

    let mut fields = Vec::new();
    let mut pending_rename: Option<String> = None;
    let mut skip_next = false;
    for line in raw[open + 1..close].lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("#[serde(") {
            if line.contains("skip") || line.contains("flatten") {
                skip_next = true;
            }
            if let Some(rename) = rust_serde_rename(line) {
                pending_rename = Some(rename);
            }
            continue;
        }
        if line.starts_with("#[") {
            continue;
        }

        let mut declaration = line.trim_end_matches(',').trim();
        if let Some(rest) = declaration.strip_prefix("pub ") {
            declaration = rest.trim();
        } else if declaration.starts_with("pub(") {
            let Some(close_visibility) = declaration.find(')') else {
                pending_rename = None;
                skip_next = false;
                continue;
            };
            declaration = declaration[close_visibility + 1..].trim();
        }
        let Some((field, _)) = declaration.split_once(':') else {
            pending_rename = None;
            skip_next = false;
            continue;
        };
        let field = field.trim();
        if !is_identifier(field) {
            pending_rename = None;
            skip_next = false;
            continue;
        }
        if !skip_next {
            let name = pending_rename.take().unwrap_or_else(|| field.to_string());
            if !name.is_empty() && name.len() <= 256 {
                fields.push(name);
            }
        } else {
            pending_rename = None;
        }
        skip_next = false;
    }
    fields.sort();
    fields.dedup();
    fields.truncate(256);
    fields
}

fn rust_serde_rename(attribute: &str) -> Option<String> {
    let marker = "rename";
    let index = attribute.find(marker)?;
    let tail = &attribute[index + marker.len()..];
    let equals = tail.find('=')?;
    first_quoted_string(&tail[equals + 1..])
}

fn rust_handler_inputs(
    source: &str,
    handlers: &BTreeMap<String, Node<'_>>,
    models: &BTreeMap<String, Vec<String>>,
) -> Vec<IndexedHandlerInput> {
    let mut output = Vec::new();
    for (name, node) in handlers {
        let Some(function_text) = text(source, *node) else {
            continue;
        };
        let mut parameters = rust_handler_parameters(function_text, models);
        normalize_parameters(&mut parameters);
        if parameters.is_empty() {
            continue;
        }
        let start = node.start_position();
        let end = node.end_position();
        output.push(IndexedHandlerInput {
            handler_name: name.clone(),
            parameters,
            start_line: start.row + 1,
            end_line: end.row + 1,
        });
    }
    output
}

fn rust_handler_parameters(
    function_text: &str,
    models: &BTreeMap<String, Vec<String>>,
) -> Vec<IndexedRouteParameter> {
    let mut output = Vec::new();
    let parameter_text = rust_function_parameter_text(function_text).unwrap_or("");
    for (marker, location) in [
        ("Query<", "query"),
        ("Json<", "json"),
        ("Form<", "form"),
        ("Path<", "path"),
    ] {
        for model in rust_generic_models(parameter_text, marker) {
            if let Some(fields) = models.get(&model) {
                for field in fields {
                    output.push(route_parameter(field, location));
                }
            }
        }
    }

    for binding in rust_header_map_bindings(parameter_text) {
        let marker = format!("{binding}.get(");
        for name in marker_quoted_arguments(function_text, &marker) {
            if !name.is_empty() && name.len() <= 256 {
                output.push(route_parameter(&name, "header"));
            }
        }
    }
    output
}

fn rust_function_parameter_text(function_text: &str) -> Option<&str> {
    let fn_index = function_text.find("fn ")?;
    let open = function_text[fn_index..].find('(')? + fn_index;
    let mut depth = 0usize;
    for (offset, character) in function_text[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&function_text[open + 1..open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

fn rust_generic_models(value: &str, marker: &str) -> Vec<String> {
    let mut output = Vec::new();
    for (index, _) in value.match_indices(marker) {
        if index > 0 {
            let previous = value[..index].chars().next_back();
            if previous.is_some_and(|character| character == '_' || character.is_ascii_alphanumeric()) {
                continue;
            }
        }
        let start = index + marker.len();
        let mut depth = 1usize;
        let mut end = None;
        for (offset, character) in value[start..].char_indices() {
            match character {
                '<' => depth += 1,
                '>' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = Some(start + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            continue;
        };
        let inner = value[start..end].trim();
        if let Some(model) = rust_simple_type_name(inner) {
            output.push(model);
        }
    }
    output.sort();
    output.dedup();
    output
}

fn rust_simple_type_name(value: &str) -> Option<String> {
    let value = value
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();
    if value.is_empty()
        || value
            .chars()
            .any(|character| matches!(character, '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';'))
        || value.chars().any(char::is_whitespace)
    {
        return None;
    }
    let name = value.rsplit("::").next().unwrap_or(value).trim();
    if is_identifier(name) {
        Some(name.to_string())
    } else {
        None
    }
}

fn rust_header_map_bindings(parameter_text: &str) -> Vec<String> {
    let mut output = Vec::new();
    for parameter in parameter_text.split(',') {
        let Some((binding, annotation)) = parameter.split_once(':') else {
            continue;
        };
        if !annotation.contains("HeaderMap") {
            continue;
        }
        let binding = binding.trim().trim_start_matches("mut ").trim();
        if is_identifier(binding) {
            output.push(binding.to_string());
        }
    }
    output
}

fn rust_request_content_type(parameters: &[IndexedRouteParameter]) -> Option<String> {
    if parameters.iter().any(|value| value.location == "json") {
        Some("application/json".to_string())
    } else if parameters.iter().any(|value| value.location == "form") {
        Some("application/x-www-form-urlencoded".to_string())
    } else {
        None
    }
}

fn axum_methods(value: &str) -> Vec<String> {
    let lower = value.to_ascii_lowercase();
    let mut methods = Vec::new();
    for method in HTTP_METHODS {
        if contains_method_call(&lower, method) {
            methods.push(method.to_ascii_uppercase());
        }
    }
    methods.sort();
    methods.dedup();
    methods
}

fn axum_method_handlers(value: &str) -> BTreeMap<String, String> {
    let lower = value.to_ascii_lowercase();
    let mut handlers = BTreeMap::new();
    for method in HTTP_METHODS {
        let needle = format!("{method}(");
        for (index, _) in lower.match_indices(&needle) {
            if index > 0 {
                let previous = lower[..index].chars().next_back();
                if previous.is_some_and(|character| character == '_' || character.is_ascii_alphanumeric()) {
                    continue;
                }
            }
            let tail = value[index + needle.len()..].trim_start();
            let candidate = tail
                .split(|character: char| character == ')' || character == ',' || character.is_whitespace())
                .next()
                .unwrap_or("")
                .trim();
            if is_identifier(candidate) {
                handlers.entry(method.to_ascii_uppercase()).or_insert_with(|| candidate.to_string());
                break;
            }
        }
    }
    handlers
}

fn contains_method_call(value: &str, method: &str) -> bool {
    let needle = format!("{method}(");
    value.match_indices(&needle).any(|(index, _)| {
        if index == 0 {
            return true;
        }
        let previous = value[..index].chars().next_back();
        previous.is_some_and(|character| {
            !(character == '_' || character.is_ascii_alphanumeric())
        })
    })
}
fn pydantic_model_fields(source: &str, root: Node<'_>) -> BTreeMap<String, Vec<String>> {
    let mut models = BTreeMap::new();
    walk(root, &mut |node| {
        if node.kind() != "class_definition" {
            return;
        }
        let Some(class_text) = text(source, node) else {
            return;
        };
        if !class_text.contains("BaseModel") {
            return;
        }
        let Some(name) = node
            .child_by_field_name("name")
            .and_then(|value| text(source, value))
        else {
            return;
        };
        let mut fields = Vec::new();
        for line in class_text.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with('@')
                || trimmed.starts_with("def ")
                || trimmed.starts_with("async def ")
                || trimmed.starts_with("class ")
            {
                continue;
            }
            let Some((candidate, _)) = trimmed.split_once(':') else {
                continue;
            };
            let candidate = candidate.trim();
            if is_identifier(candidate) {
                fields.push(candidate.to_string());
            }
        }
        fields.sort();
        fields.dedup();
        if !fields.is_empty() {
            models.insert(name.to_string(), fields);
        }
    });
    models
}

fn fastapi_router_prefixes(
    source: &str,
    root: Node<'_>,
) -> (BTreeMap<String, String>, Vec<IndexedRouteMount>) {
    let mut prefixes = BTreeMap::<String, String>::new();
    let mut mounts = Vec::new();
    walk(root, &mut |node| {
        if node.kind() == "assignment" {
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return;
            };
            let Some(name) = text(source, left).map(str::trim) else {
                return;
            };
            let Some(value) = text(source, right) else {
                return;
            };
            if is_identifier(name) && value.contains("APIRouter(") {
                if let Some(prefix) = keyword_string(value, "prefix") {
                    prefixes.insert(name.to_string(), normalize_path(&prefix));
                }
            }
        }

        if node.kind() == "call" {
            let Some(value) = text(source, node) else {
                return;
            };
            if !value.contains(".include_router(") {
                return;
            }
            let Some(open) = value.find(".include_router(") else {
                return;
            };
            let parent_router = value[..open].trim();
            if !is_identifier(parent_router) {
                return;
            }
            let tail = &value[open + ".include_router(".len()..];
            let child = tail
                .split([',', ')'])
                .next()
                .map(str::trim)
                .filter(|candidate| is_identifier(candidate));
            let Some(child) = child else {
                return;
            };
            if let Some(prefix) = keyword_string(value, "prefix") {
                let existing = prefixes.get(child).cloned().unwrap_or_default();
                prefixes.insert(child.to_string(), combine_paths(Some(&prefix), &existing));
                let start = node.start_position();
                let end = node.end_position();
                mounts.push(IndexedRouteMount {
                    framework: "fastapi".to_string(),
                    parent_router: parent_router.to_string(),
                    mounted_binding: child.to_string(),
                    prefix: normalize_path(&prefix),
                    prefix_mode: "prepend".to_string(),
                    start_line: start.row + 1,
                    end_line: end.row + 1,
                });
            } else {
                let start = node.start_position();
                let end = node.end_position();
                mounts.push(IndexedRouteMount {
                    framework: "fastapi".to_string(),
                    parent_router: parent_router.to_string(),
                    mounted_binding: child.to_string(),
                    prefix: "/".to_string(),
                    prefix_mode: "prepend".to_string(),
                    start_line: start.row + 1,
                    end_line: end.row + 1,
                });
            }
        }
    });
    (prefixes, mounts)
}

fn fastapi_function_parameters(
    source: &str,
    function: Node<'_>,
    path: &str,
    model_fields: &BTreeMap<String, Vec<String>>,
) -> Vec<IndexedRouteParameter> {
    let Some(parameters_node) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut output = Vec::new();
    for parameter in named_children(parameters_node) {
        let Some(raw) = text(source, parameter).map(str::trim) else {
            continue;
        };
        let name = raw
            .trim_start_matches('*')
            .split([':', '='])
            .next()
            .map(str::trim)
            .unwrap_or("");
        if !is_identifier(name) || matches!(name, "self" | "cls") {
            continue;
        }
        if path.contains(&format!("{{{name}}}")) {
            output.push(route_parameter(name, "path"));
            continue;
        }
        let explicit = [
            ("Path(", "path"),
            ("Query(", "query"),
            ("Header(", "header"),
            ("Cookie(", "cookie"),
            ("Form(", "form"),
            ("File(", "form"),
            ("Body(", "json"),
        ]
        .into_iter()
        .find(|(marker, _)| raw.contains(marker))
        .map(|(_, location)| location);
        if let Some(location) = explicit {
            output.push(route_parameter(name, location));
            continue;
        }

        let annotation = raw
            .split_once(':')
            .map(|(_, tail)| tail.split('=').next().unwrap_or(tail).trim())
            .unwrap_or("");
        let mut expanded_model = false;
        for (model, fields) in model_fields {
            if annotation_contains_type(annotation, model) {
                for field in fields {
                    output.push(route_parameter(field, "json"));
                }
                expanded_model = true;
                break;
            }
        }
        if !expanded_model {
            output.push(route_parameter(name, "query"));
        }
    }
    output
}

fn parse_fastapi_decorator(value: &str) -> Option<(String, String, String)> {
    let trimmed = value.trim().trim_start_matches('@');
    for method in HTTP_METHODS {
        let marker = format!(".{method}(");
        let Some(index) = trimmed.find(&marker) else {
            continue;
        };
        let router = trimmed[..index].trim();
        if !is_identifier(router) {
            continue;
        }
        let args = &trimmed[index + marker.len()..];
        let path = first_quoted_string(args)?;
        return Some((router.to_string(), (*method).to_string(), path));
    }
    None
}

fn member_call(source: &str, node: Node<'_>) -> Option<(String, String)> {
    let function = node.child_by_field_name("function")?;
    if function.kind() != "member_expression" {
        return None;
    }
    let object = function.child_by_field_name("object")?;
    let property = function.child_by_field_name("property")?;
    let object = text(source, object)?.trim();
    let property = text(source, property)?.trim();
    if !is_identifier(object) || !is_identifier(property) {
        return None;
    }
    Some((object.to_string(), property.to_ascii_lowercase()))
}

fn static_string(source: &str, node: Node<'_>) -> Option<String> {
    let raw = text(source, node)?.trim();
    match node.kind() {
        "string" => strip_quotes(raw),
        "template_string" if !raw.contains("${") => {
            raw.strip_prefix('\u{0060}')
                .and_then(|value| value.strip_suffix('\u{0060}'))
                .map(ToString::to_string)
        }
        _ => None,
    }
}

fn strip_quotes(value: &str) -> Option<String> {
    let first = value.chars().next()?;
    if !matches!(first, '"' | '\'') || !value.ends_with(first) || value.len() < 2 {
        return None;
    }
    Some(value[1..value.len() - 1].to_string())
}

fn first_quoted_string(value: &str) -> Option<String> {
    for (index, character) in value.char_indices() {
        if matches!(character, '"' | '\'' | '`') {
            let tail = &value[index + character.len_utf8()..];
            let end = tail.find(character)?;
            return Some(tail[..end].to_string());
        }
    }
    None
}

fn keyword_value_tail<'a>(value: &'a str, keyword: &str) -> Option<&'a str> {
    let mut offset = 0usize;
    while let Some(relative) = value[offset..].find(keyword) {
        let index = offset + relative;
        let before_ok = index == 0
            || !value[..index]
                .chars()
                .next_back()
                .is_some_and(|character| character == '_' || character.is_ascii_alphanumeric());
        let after_keyword = &value[index + keyword.len()..];
        let trimmed = after_keyword.trim_start();
        if before_ok {
            if let Some(rest) = trimmed.strip_prefix('=') {
                return Some(rest.trim_start());
            }
        }
        offset = index + keyword.len();
    }
    None
}

fn keyword_string(value: &str, keyword: &str) -> Option<String> {
    first_quoted_string(keyword_value_tail(value, keyword)?)
}

fn keyword_quoted_strings(value: &str, keyword: &str) -> Vec<String> {
    let Some(tail) = keyword_value_tail(value, keyword) else {
        return Vec::new();
    };
    let end = tail
        .find(']')
        .or_else(|| tail.find(')'))
        .unwrap_or(tail.len());
    quoted_strings(&tail[..end])
}

fn quoted_strings(value: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut chars = value.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if !matches!(character, '"' | '\'' | '`') {
            continue;
        }
        let start = index + character.len_utf8();
        let tail = &value[start..];
        let Some(end) = tail.find(character) else {
            break;
        };
        output.push(tail[..end].to_string());
        while let Some((next_index, _)) = chars.peek().copied() {
            if next_index < start + end + character.len_utf8() {
                chars.next();
            } else {
                break;
            }
        }
    }
    output
}

fn path_parameters(path: &str) -> Vec<IndexedRouteParameter> {
    let mut values = Vec::new();
    for segment in path.split('/') {
        if let Some(name) = segment.strip_prefix(':') {
            let name = name
                .split(['?', '(', '.'])
                .next()
                .unwrap_or(name)
                .trim();
            if is_identifier(name) {
                values.push(route_parameter(name, "path"));
            }
        }
        if segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2 {
            let name = segment[1..segment.len() - 1]
                .split([':', '?'])
                .next()
                .unwrap_or("")
                .trim();
            if is_identifier(name) {
                values.push(route_parameter(name, "path"));
            }
        }
        if segment.starts_with('<') && segment.ends_with('>') && segment.len() > 2 {
            let inner = &segment[1..segment.len() - 1];
            let name = inner.rsplit_once(':').map(|(_, name)| name).unwrap_or(inner).trim();
            if is_identifier(name) {
                values.push(route_parameter(name, "path"));
            }
        }
    }
    values
}

fn route_parameter(name: &str, location: &str) -> IndexedRouteParameter {
    IndexedRouteParameter {
        name: name.to_string(),
        location: location.to_string(),
    }
}

fn normalize_parameters(parameters: &mut Vec<IndexedRouteParameter>) {
    parameters.sort_by(|left, right| {
        (&left.location, &left.name).cmp(&(&right.location, &right.name))
    });
    parameters.dedup_by(|left, right| left.location == right.location && left.name == right.name);
    parameters.truncate(256);
}

fn combine_paths(prefix: Option<&str>, path: &str) -> String {
    let prefix = prefix.unwrap_or("").trim();
    let path = path.trim();
    if prefix.is_empty() {
        return normalize_path(path);
    }
    if path.is_empty() || path == "/" {
        return normalize_path(prefix);
    }
    normalize_path(&format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        path.trim_start_matches('/')
    ))
}

fn normalize_path(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    let mut path = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    if path.len() > 1 {
        path = path.trim_end_matches('/').to_string();
    }
    path
}

fn annotation_contains_type(annotation: &str, type_name: &str) -> bool {
    annotation
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == type_name)
}

fn is_function_like(node: Node<'_>) -> bool {
    matches!(node.kind(), "arrow_function" | "function_expression" | "function")
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn collect_identifiers(source: &str, node: Node<'_>, callback: &mut impl FnMut(&str)) {
    if node.kind() == "identifier" {
        if let Some(value) = text(source, node) {
            callback(value.trim());
        }
        return;
    }
    for child in named_children(node) {
        collect_identifiers(source, child, callback);
    }
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .collect()
}

fn walk(node: Node<'_>, callback: &mut impl FnMut(Node<'_>)) {
    callback(node);
    for child in named_children(node) {
        walk(child, callback);
    }
}

fn text<'a>(source: &'a str, node: Node<'_>) -> Option<&'a str> {
    node.utf8_text(source.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use tree_sitter::Parser;

    use super::extract_routes;

    #[test]
    fn nextjs_function_body_does_not_create_fake_exported_methods() {
        let source = r#"
export function GET() {
  const methods = { POST: true };
  return Response.json(methods);
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes(
            "TypeScript",
            "app/status/route.ts",
            source,
            tree.root_node(),
        );
        assert!(routes
            .iter()
            .any(|route| route.framework == "nextjs" && route.http_method == "GET"));
        assert!(!routes
            .iter()
            .any(|route| route.framework == "nextjs" && route.http_method == "POST"));
    }

    #[test]
    fn extracts_nextjs_reexported_methods_and_catch_all_path() {
        let source = r#"
export { GET, handler as POST } from "./handlers";
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes(
            "TypeScript",
            "app/docs/[...slug]/route.ts",
            source,
            tree.root_node(),
        );
        for method in ["GET", "POST"] {
            let route = routes
                .iter()
                .find(|route| route.framework == "nextjs" && route.http_method == method)
                .expect("re-exported Next.js method");
            assert_eq!(route.path_template, "/docs/{slug}");
            assert!(route
                .parameters
                .iter()
                .any(|parameter| parameter.name == "slug" && parameter.location == "path"));
        }
    }

    #[test]
    fn materializes_nextjs_optional_catch_all_with_safe_single_segment() {
        let source = "export function GET() { return new Response('ok'); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes(
            "TypeScript",
            "src/app/blog/[[...slug]]/route.ts",
            source,
            tree.root_node(),
        );
        let route = routes
            .iter()
            .find(|route| route.framework == "nextjs" && route.http_method == "GET")
            .expect("optional catch-all route");
        assert_eq!(route.path_template, "/blog/{slug}");
    }

    #[test]
    fn extracts_nextjs_app_router_methods_and_dynamic_path() {
        let source = r#"
export async function GET(request: Request) {
  return Response.json({ ok: true });
}

export const POST = async (request: Request) => {
  return Response.json({ created: true });
};
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes(
            "TypeScript",
            "src/app/(dashboard)/users/[id]/route.ts",
            source,
            tree.root_node(),
        );
        let get = routes
            .iter()
            .find(|route| route.framework == "nextjs" && route.http_method == "GET")
            .expect("nextjs GET");
        assert_eq!(get.path_template, "/users/{id}");
        assert!(get
            .parameters
            .iter()
            .any(|parameter| parameter.name == "id" && parameter.location == "path"));
        assert!(routes
            .iter()
            .any(|route| route.framework == "nextjs" && route.http_method == "POST"));
    }

    #[test]
    fn maps_nextjs_request_inputs_to_source_routes() {
        let source = r#"
import { NextRequest } from "next/server";

export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get("q");
  const params = request.nextUrl.searchParams;
  const page = params.get("page");
  const tenant = request.headers.get("X-Tenant");
  const dynamic = "secret";
  request.nextUrl.searchParams.get(dynamic);
  return Response.json({ q, page, tenant });
}

export async function POST(request: Request) {
  const { email, password: secret } = await request.json();
  return Response.json({ email, secret });
}

export async function PUT(request: Request) {
  const payload = await request.json();
  return Response.json({
    name: payload.displayName,
    timezone: payload["timezone"],
  });
}

export const PATCH = async (request: Request) => {
  const form = await request.formData();
  const avatar = form.get("avatar");
  return Response.json({ avatar });
};
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, handler_inputs) = extract_routes(
            "TypeScript",
            "src/app/users/[id]/route.ts",
            source,
            tree.root_node(),
        );

        let get = routes
            .iter()
            .find(|route| route.framework == "nextjs" && route.http_method == "GET")
            .expect("GET route");
        assert_eq!(get.handler_name.as_deref(), Some("GET"));
        for field in ["q", "page"] {
            assert!(get.parameters.iter().any(|parameter| {
                parameter.name == field && parameter.location == "query"
            }));
        }
        assert!(get.parameters.iter().any(|parameter| {
            parameter.name == "X-Tenant" && parameter.location == "header"
        }));
        assert!(!get.parameters.iter().any(|parameter| parameter.name == "secret"));
        assert!(get.parameters.iter().any(|parameter| {
            parameter.name == "id" && parameter.location == "path"
        }));

        let post = routes
            .iter()
            .find(|route| route.framework == "nextjs" && route.http_method == "POST")
            .expect("POST route");
        for field in ["email", "password"] {
            assert!(post.parameters.iter().any(|parameter| {
                parameter.name == field && parameter.location == "json"
            }));
        }
        assert_eq!(post.request_content_type.as_deref(), Some("application/json"));

        let put = routes
            .iter()
            .find(|route| route.framework == "nextjs" && route.http_method == "PUT")
            .expect("PUT route");
        for field in ["displayName", "timezone"] {
            assert!(put.parameters.iter().any(|parameter| {
                parameter.name == field && parameter.location == "json"
            }));
        }

        let patch = routes
            .iter()
            .find(|route| route.framework == "nextjs" && route.http_method == "PATCH")
            .expect("PATCH route");
        assert!(patch.parameters.iter().any(|parameter| {
            parameter.name == "avatar" && parameter.location == "form"
        }));
        assert_eq!(
            patch.request_content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );

        assert!(handler_inputs.iter().any(|input| {
            input.handler_name == "GET"
                && input.parameters.iter().any(|parameter| {
                    parameter.name == "X-Tenant" && parameter.location == "header"
                })
        }));
    }

    #[test]
    fn preserves_local_handler_identity_for_nextjs_named_reexport() {
        let source = r#"
async function create(request: Request) {
  const { email } = await request.json();
  return Response.json({ email });
}

export { create as POST };
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, handler_inputs) = extract_routes(
            "TypeScript",
            "app/users/route.ts",
            source,
            tree.root_node(),
        );
        let route = routes
            .iter()
            .find(|route| route.framework == "nextjs" && route.http_method == "POST")
            .expect("named re-export route");
        assert_eq!(route.handler_name.as_deref(), Some("create"));
        assert!(route.parameters.iter().any(|parameter| {
            parameter.name == "email" && parameter.location == "json"
        }));
        assert!(handler_inputs.iter().any(|input| {
            input.handler_name == "create"
                && input.parameters.iter().any(|parameter| {
                    parameter.name == "email" && parameter.location == "json"
                })
        }));
    }
    #[test]
    fn extracts_express_route_inputs_and_mount_prefix() {
        let source = r#"
const express = require("express");
const app = express();
const auth = express.Router();
app.use("/api", auth);
const login = (req, res) => {
  const { email, password } = req.body;
  const next = req.query.next;
  return res.json({ ok: true, next });
};
auth.post("/login/:tenant", login);
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, handler_inputs) = extract_routes("JavaScript", "src/server.js", source, tree.root_node());
        let route = routes.iter().find(|value| value.path_template == "/api/login/:tenant").expect("route");
        assert_eq!(route.http_method, "POST");
        assert!(route.parameters.iter().any(|value| value.name == "tenant" && value.location == "path"));
        assert!(route.parameters.iter().any(|value| value.name == "email" && value.location == "json"));
        assert!(route.parameters.iter().any(|value| value.name == "password" && value.location == "json"));
        assert!(route.parameters.iter().any(|value| value.name == "next" && value.location == "query"));
        let handler = handler_inputs.iter().find(|value| value.handler_name == "login").expect("handler");
        assert!(handler.parameters.iter().any(|value| value.name == "email" && value.location == "json"));
        assert!(handler.parameters.iter().any(|value| value.name == "next" && value.location == "query"));
    }

    #[test]
    fn extracts_cross_file_mount_candidates() {
        let source = r#"
import authRouter from "./routes/auth";
app.use("/api/auth", authRouter);
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (_routes, mounts, _handler_inputs) = extract_routes("JavaScript", "src/server.js", source, tree.root_node());
        let mount = mounts.iter().find(|value| value.mounted_binding == "authRouter").expect("mount");
        assert_eq!(mount.prefix, "/api/auth");
        assert_eq!(mount.framework, "express");
    }

    #[test]
    fn extracts_flask_routes_blueprints_and_converters() {
        let source = r#"
from flask import Flask, Blueprint

app = Flask(__name__)
api = Blueprint("api", __name__, url_prefix = "/v1")

@app.route("/health", methods = ["GET", "HEAD"])
def health():
    return "ok"

@api.post("/users/<int:user_id>")
def create_user(user_id):
    return {"id": user_id}

app.register_blueprint(api, url_prefix = "/api")
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, mounts, _handler_inputs) = extract_routes("Python", "app.py", source, tree.root_node());
        assert!(routes.iter().any(|route| {
            route.framework == "flask"
                && route.http_method == "GET"
                && route.path_template == "/health"
        }));
        assert!(routes.iter().any(|route| {
            route.framework == "flask"
                && route.http_method == "HEAD"
                && route.path_template == "/health"
        }));
        let user = routes
            .iter()
            .find(|route| {
                route.framework == "flask"
                    && route.http_method == "POST"
                    && route.path_template == "/api/users/<int:user_id>"
            })
            .expect("flask typed route");
        assert!(user
            .parameters
            .iter()
            .any(|parameter| parameter.name == "user_id" && parameter.location == "path"));
        assert!(mounts.iter().any(|mount| {
            mount.framework == "flask"
                && mount.parent_router == "app"
                && mount.mounted_binding == "api"
                && mount.prefix == "/api"
        }));
    }

    #[test]
    fn expands_laravel_resource_and_api_resource_routes() {
        let source = r#"<?php
use Illuminate\Support\Facades\Route;

Route::prefix('api')->group(function () {
    Route::resource('/photos', PhotoController::class);
    Route::apiResource('/categories', CategoryController::class);
});
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes(
            "PHP",
            "routes/api.php",
            source,
            tree.root_node(),
        );

        for (method, path) in [
            ("GET", "/api/photos"),
            ("POST", "/api/photos"),
            ("GET", "/api/photos/create"),
            ("GET", "/api/photos/{photo}"),
            ("GET", "/api/photos/{photo}/edit"),
            ("PUT", "/api/photos/{photo}"),
            ("PATCH", "/api/photos/{photo}"),
            ("DELETE", "/api/photos/{photo}"),
            ("GET", "/api/categories"),
            ("POST", "/api/categories"),
            ("GET", "/api/categories/{category}"),
            ("PUT", "/api/categories/{category}"),
            ("PATCH", "/api/categories/{category}"),
            ("DELETE", "/api/categories/{category}"),
        ] {
            assert!(
                routes.iter().any(|route| {
                    route.framework == "laravel"
                        && route.http_method == method
                        && route.path_template == path
                }),
                "missing {method} {path}: {routes:?}"
            );
        }
        assert!(!routes.iter().any(|route| {
            route.path_template == "/api/categories/create"
                || route.path_template == "/api/categories/{category}/edit"
        }));
    }

    #[test]
    fn composes_nested_laravel_route_group_prefixes() {
        let source = r#"<?php
use Illuminate\Support\Facades\Route;

Route::prefix('api')->group(function () {
    Route::middleware('auth')->prefix('v1')->group(function () {
        Route::get('/users/{id}', [UserController::class, 'show']);
    });
});
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes(
            "PHP",
            "routes/api.php",
            source,
            tree.root_node(),
        );
        let route = routes
            .iter()
            .find(|route| {
                route.framework == "laravel"
                    && route.http_method == "GET"
                    && route.path_template == "/api/v1/users/{id}"
            })
            .expect("nested Laravel group route");
        assert!(route
            .parameters
            .iter()
            .any(|parameter| parameter.name == "id" && parameter.location == "path"));
    }

    #[test]
    fn composes_laravel_array_group_prefix() {
        let source = r#"<?php
Route::group(['prefix' => 'admin'], function () {
    Route::post('/users', [UserController::class, 'store']);
});
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes(
            "PHP",
            "routes/web.php",
            source,
            tree.root_node(),
        );
        assert!(routes.iter().any(|route| {
            route.framework == "laravel"
                && route.http_method == "POST"
                && route.path_template == "/admin/users"
        }));
    }

    #[test]
    fn extracts_laravel_route_facade_calls() {
        let source = r#"<?php
use Illuminate\Support\Facades\Route;

Route::get('/users/{id?}', [UserController::class, 'show']);
Route::post('/login', [AuthController::class, 'login']);
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes("PHP", "routes/web.php", source, tree.root_node());
        let user = routes
            .iter()
            .find(|route| {
                route.framework == "laravel"
                    && route.http_method == "GET"
                    && route.path_template == "/users/{id?}"
            })
            .expect("laravel get route");
        assert!(user
            .parameters
            .iter()
            .any(|parameter| parameter.name == "id" && parameter.location == "path"));
        assert!(routes.iter().any(|route| {
            route.framework == "laravel"
                && route.http_method == "POST"
                && route.path_template == "/login"
        }));
    }

    #[test]
    fn maps_go_json_struct_fields_from_explicit_body_binding() {
        let source = r#"
package main

import (
    "encoding/json"
    "github.com/gin-gonic/gin"
)

type CreateUserRequest struct {
    Email string `json:"email"`
    Password string `json:"password,omitempty"`
    DisplayName string
    Ignored string `json:"-"`
    private string `json:"private"`
}

func createUser(c *gin.Context) {
    var payload CreateUserRequest
    if err := c.ShouldBindJSON(&payload); err != nil {
        return
    }
}

func decodeUser(c *gin.Context) {
    payload := CreateUserRequest{}
    if err := json.NewDecoder(c.Request.Body).Decode(&payload); err != nil {
        return
    }
}

func routes(r *gin.Engine) {
    r.POST("/users", createUser)
    r.PUT("/users/:id", decodeUser)
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _, handler_inputs) =
            extract_routes("Go", "main.go", source, tree.root_node());

        let create = routes
            .iter()
            .find(|route| route.http_method == "POST" && route.path_template == "/users")
            .expect("create route");
        for field in ["email", "password", "DisplayName"] {
            assert!(create.parameters.iter().any(|parameter| {
                parameter.name == field && parameter.location == "json"
            }));
        }
        assert!(!create.parameters.iter().any(|parameter| parameter.name == "Ignored"));
        assert!(!create.parameters.iter().any(|parameter| parameter.name == "private"));
        assert_eq!(create.request_content_type.as_deref(), Some("application/json"));

        let update = routes
            .iter()
            .find(|route| route.http_method == "PUT" && route.path_template == "/users/:id")
            .expect("update route");
        assert!(update.parameters.iter().any(|parameter| {
            parameter.name == "email" && parameter.location == "json"
        }));
        assert!(update.parameters.iter().any(|parameter| {
            parameter.name == "id" && parameter.location == "path"
        }));

        assert!(handler_inputs.iter().any(|input| {
            input.handler_name == "decodeUser"
                && input.parameters.iter().any(|parameter| {
                    parameter.name == "password" && parameter.location == "json"
                })
        }));
    }

    #[test]
    fn does_not_infer_json_from_generic_bind_or_embedded_schema() {
        let source = r#"
package main

import "github.com/labstack/echo/v4"

type Address struct {
    City string `json:"city"`
}

type Request struct {
    Email string `json:"email"`
    Address
}

func create(c echo.Context) error {
    payload := Request{}
    return c.Bind(&payload)
}

func routes(e *echo.Echo) {
    e.POST("/users", create)
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _, _) = extract_routes("Go", "echo.go", source, tree.root_node());
        let route = routes.iter().find(|route| route.framework == "echo").expect("echo");
        assert!(!route.parameters.iter().any(|parameter| parameter.location == "json"));
    }
    #[test]
    fn maps_gin_handler_inputs_back_to_source_route() {
        let source = r#"
package main

import "github.com/gin-gonic/gin"

func showUser(c *gin.Context) {
    id := c.Param("id")
    expand := c.Query("expand")
    locale := c.DefaultQuery("locale", "en")
    token := c.GetHeader("X-Token")
    _ = id
    _ = expand
    _ = locale
    _ = token
}

func createUser(c *gin.Context) {
    email := c.PostForm("email")
    _ = email
}

func routes(r *gin.Engine) {
    r.GET("/users/:id", showUser)
    r.POST("/users", createUser)
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _, handler_inputs) =
            extract_routes("Go", "main.go", source, tree.root_node());

        let show = routes
            .iter()
            .find(|route| route.http_method == "GET" && route.path_template == "/users/:id")
            .expect("gin GET route");
        assert_eq!(show.handler_name.as_deref(), Some("showUser"));
        assert!(show.parameters.iter().any(|parameter| {
            parameter.name == "id" && parameter.location == "path"
        }));
        assert!(show.parameters.iter().any(|parameter| {
            parameter.name == "expand" && parameter.location == "query"
        }));
        assert!(show.parameters.iter().any(|parameter| {
            parameter.name == "locale" && parameter.location == "query"
        }));
        assert!(show.parameters.iter().any(|parameter| {
            parameter.name == "X-Token" && parameter.location == "header"
        }));

        let create = routes
            .iter()
            .find(|route| route.http_method == "POST" && route.path_template == "/users")
            .expect("gin POST route");
        assert_eq!(create.handler_name.as_deref(), Some("createUser"));
        assert!(create.parameters.iter().any(|parameter| {
            parameter.name == "email" && parameter.location == "form"
        }));
        assert_eq!(
            create.request_content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        assert!(handler_inputs.iter().any(|input| {
            input.handler_name == "showUser"
                && input
                    .parameters
                    .iter()
                    .any(|parameter| parameter.name == "expand" && parameter.location == "query")
        }));
    }

    #[test]
    fn maps_echo_chi_and_stdlib_handler_inputs_without_dynamic_key_guessing() {
        let echo = r#"
package main
import "github.com/labstack/echo/v4"
func login(c echo.Context) error {
    next := c.QueryParam("next")
    tenant := c.Param("tenant")
    csrf := c.FormValue("csrf")
    _ = next
    _ = tenant
    _ = csrf
    return nil
}
func routes(e *echo.Echo) { e.POST("/login/:tenant", login) }
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(echo, None).expect("tree");
        let (routes, _, _) = extract_routes("Go", "echo.go", echo, tree.root_node());
        let route = routes.iter().find(|route| route.framework == "echo").expect("echo");
        assert!(route.parameters.iter().any(|parameter| parameter.name == "next" && parameter.location == "query"));
        assert!(route.parameters.iter().any(|parameter| parameter.name == "csrf" && parameter.location == "form"));

        let chi = r#"
package main
import "github.com/go-chi/chi/v5"
func show(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    q := r.URL.Query().Get("q")
    _ = id
    _ = q
}
func routes(r chi.Router) { r.Get("/items/{id}", show) }
"#;
        let tree = parser.parse(chi, None).expect("tree");
        let (routes, _, _) = extract_routes("Go", "chi.go", chi, tree.root_node());
        let route = routes.iter().find(|route| route.framework == "chi").expect("chi");
        assert!(route.parameters.iter().any(|parameter| parameter.name == "id" && parameter.location == "path"));
        assert!(route.parameters.iter().any(|parameter| parameter.name == "q" && parameter.location == "query"));

        let stdlib = r#"
package main
import "net/http"
func user(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    q := r.URL.Query().Get("q")
    dynamic := "secret"
    _ = r.URL.Query().Get(dynamic)
    _ = id
    _ = q
}
func routes(mux *http.ServeMux) { mux.HandleFunc("GET /users/{id}", user) }
"#;
        let tree = parser.parse(stdlib, None).expect("tree");
        let (routes, _, _) = extract_routes("Go", "main.go", stdlib, tree.root_node());
        let route = routes.iter().find(|route| route.framework == "go-stdlib").expect("stdlib");
        assert!(route.parameters.iter().any(|parameter| parameter.name == "id" && parameter.location == "path"));
        assert!(route.parameters.iter().any(|parameter| parameter.name == "q" && parameter.location == "query"));
        assert!(!route.parameters.iter().any(|parameter| parameter.name == "secret"));
    }

    #[test]
    fn extracts_go_stdlib_method_qualified_servemux_patterns_only() {
        let source = r#"
package main

import "net/http"

func routes(mux *http.ServeMux, client *http.Client) {
    mux.HandleFunc("GET /users/{id}", user)
    http.HandleFunc("POST /login", login)
    mux.HandleFunc("/health", health)
    client.Get("/not-a-server-route")
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _, _) = extract_routes("Go", "main.go", source, tree.root_node());
        let user = routes
            .iter()
            .find(|route| {
                route.framework == "go-stdlib"
                    && route.http_method == "GET"
                    && route.path_template == "/users/{id}"
            })
            .expect("stdlib GET route");
        assert!(user
            .parameters
            .iter()
            .any(|parameter| parameter.name == "id" && parameter.location == "path"));
        assert!(routes.iter().any(|route| {
            route.framework == "go-stdlib"
                && route.http_method == "POST"
                && route.path_template == "/login"
        }));
        assert!(!routes.iter().any(|route| route.path_template == "/health"));
        assert!(!routes
            .iter()
            .any(|route| route.path_template == "/not-a-server-route"));
    }

    #[test]
    fn extracts_gin_routes_and_nested_groups() {
        let source = r#"
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    api := r.Group("/api")
    v1 := api.Group("/v1")
    v1.GET("/users/:id", showUser)
    v1.POST(`/users`, createUser)
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, mounts, _handler_inputs) =
            extract_routes("Go", "main.go", source, tree.root_node());
        let get = routes
            .iter()
            .find(|route| {
                route.framework == "gin"
                    && route.http_method == "GET"
                    && route.path_template == "/api/v1/users/:id"
            })
            .expect("gin GET route");
        assert!(get
            .parameters
            .iter()
            .any(|parameter| parameter.name == "id" && parameter.location == "path"));
        assert!(routes.iter().any(|route| {
            route.framework == "gin"
                && route.http_method == "POST"
                && route.path_template == "/api/v1/users"
        }));
        assert!(mounts.iter().any(|mount| {
            mount.framework == "gin"
                && mount.parent_router == "r"
                && mount.mounted_binding == "api"
                && mount.prefix == "/api"
        }));
    }

    #[test]
    fn extracts_echo_and_chi_static_routes_without_generic_go_false_positives() {
        let echo = r#"
package main
import "github.com/labstack/echo/v4"
func routes(e *echo.Echo) {
    e.GET("/health", health)
    e.Add("POST", "/login", login)
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(echo, None).expect("tree");
        let (routes, _, _) = extract_routes("Go", "echo.go", echo, tree.root_node());
        assert!(routes.iter().any(|route| {
            route.framework == "echo"
                && route.http_method == "GET"
                && route.path_template == "/health"
        }));
        assert!(routes.iter().any(|route| {
            route.framework == "echo"
                && route.http_method == "POST"
                && route.path_template == "/login"
        }));

        let chi = r#"
package main
import "github.com/go-chi/chi/v5"
func routes(r chi.Router) {
    r.Get("/articles/{id}", show)
}
"#;
        let tree = parser.parse(chi, None).expect("tree");
        let (routes, _, _) = extract_routes("Go", "chi.go", chi, tree.root_node());
        assert!(routes.iter().any(|route| {
            route.framework == "chi"
                && route.http_method == "GET"
                && route.path_template == "/articles/{id}"
        }));

        let generic = r#"
package main
func fetch(client *Client) {
    client.Get("/not-a-server-route")
}
"#;
        let tree = parser.parse(generic, None).expect("tree");
        let (routes, _, _) = extract_routes("Go", "client.go", generic, tree.root_node());
        assert!(routes.is_empty());
    }

    #[test]
    fn maps_axum_typed_extractors_and_static_header_keys_to_routes() {
        let source = r#"
use axum::{
    extract::{Path, Query},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct ListQuery {
    #[serde(rename = "pageSize")]
    page_size: usize,
    q: String,
}

#[derive(Deserialize)]
struct CreateUser {
    email: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(skip)]
    ignored: String,
}

async fn list(Query(_query): Query<ListQuery>, headers: HeaderMap) {
    let _ = headers.get("X-Tenant");
}

async fn update(Path(_id): Path<String>, Json(_body): Json<CreateUser>) {}

fn app() -> Router {
    Router::new()
        .route("/users", get(list))
        .route("/users/{id}", post(update))
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _, handler_inputs) =
            extract_routes("Rust", "src/main.rs", source, tree.root_node());

        let list = routes
            .iter()
            .find(|route| route.http_method == "GET" && route.path_template == "/users")
            .expect("axum list route");
        assert_eq!(list.handler_name.as_deref(), Some("list"));
        assert!(list.parameters.iter().any(|parameter| {
            parameter.name == "pageSize" && parameter.location == "query"
        }));
        assert!(list.parameters.iter().any(|parameter| {
            parameter.name == "q" && parameter.location == "query"
        }));
        assert!(list.parameters.iter().any(|parameter| {
            parameter.name == "X-Tenant" && parameter.location == "header"
        }));

        let update = routes
            .iter()
            .find(|route| route.http_method == "POST" && route.path_template == "/users/{id}")
            .expect("axum update route");
        assert_eq!(update.handler_name.as_deref(), Some("update"));
        assert!(update.parameters.iter().any(|parameter| {
            parameter.name == "id" && parameter.location == "path"
        }));
        assert!(update.parameters.iter().any(|parameter| {
            parameter.name == "email" && parameter.location == "json"
        }));
        assert!(update.parameters.iter().any(|parameter| {
            parameter.name == "displayName" && parameter.location == "json"
        }));
        assert!(!update.parameters.iter().any(|parameter| parameter.name == "ignored"));
        assert_eq!(update.request_content_type.as_deref(), Some("application/json"));

        assert!(handler_inputs.iter().any(|input| {
            input.handler_name == "list"
                && input.parameters.iter().any(|parameter| {
                    parameter.name == "X-Tenant" && parameter.location == "header"
                })
        }));
    }

    #[test]
    fn maps_actix_form_and_rocket_json_query_inputs() {
        let actix = r#"
use actix_web::{post, web};
use serde::Deserialize;

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    csrf: String,
}

#[post("/login")]
async fn login(form: web::Form<LoginForm>) {
    let _ = form;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(actix, None).expect("tree");
        let (routes, _, _) = extract_routes("Rust", "src/actix.rs", actix, tree.root_node());
        let login = routes.iter().find(|route| route.framework == "actix-web").expect("actix route");
        assert_eq!(login.handler_name.as_deref(), Some("login"));
        assert!(login.parameters.iter().any(|parameter| parameter.name == "email" && parameter.location == "form"));
        assert!(login.parameters.iter().any(|parameter| parameter.name == "csrf" && parameter.location == "form"));
        assert_eq!(login.request_content_type.as_deref(), Some("application/x-www-form-urlencoded"));

        let rocket = r#"
use rocket::{get, post};
use rocket::serde::json::Json;
use serde::Deserialize;

#[derive(Deserialize)]
struct CreateItem {
    name: String,
}

#[get("/search?<page>&<q>")]
fn search(page: usize, q: &str) {
    let _ = (page, q);
}

#[post("/items")]
fn create(body: Json<CreateItem>) {
    let _ = body;
}
"#;
        let tree = parser.parse(rocket, None).expect("tree");
        let (routes, _, _) = extract_routes("Rust", "src/rocket.rs", rocket, tree.root_node());
        let search = routes
            .iter()
            .find(|route| route.framework == "rocket" && route.http_method == "GET")
            .expect("rocket search route");
        assert_eq!(search.path_template, "/search");
        assert!(search.parameters.iter().any(|parameter| parameter.name == "page" && parameter.location == "query"));
        assert!(search.parameters.iter().any(|parameter| parameter.name == "q" && parameter.location == "query"));

        let create = routes
            .iter()
            .find(|route| route.framework == "rocket" && route.http_method == "POST")
            .expect("rocket create route");
        assert_eq!(create.handler_name.as_deref(), Some("create"));
        assert!(create.parameters.iter().any(|parameter| parameter.name == "name" && parameter.location == "json"));
        assert_eq!(create.request_content_type.as_deref(), Some("application/json"));
    }
    #[test]
    fn extracts_actix_and_rocket_attribute_routes() {
        let actix = r#"
use actix_web::{get, post};

#[get("/users/{id}")]
async fn user() {}

#[post("/login")]
async fn login() {}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(actix, None).expect("tree");
        let (routes, _, _) = extract_routes("Rust", "src/main.rs", actix, tree.root_node());
        let user = routes
            .iter()
            .find(|route| {
                route.framework == "actix-web"
                    && route.http_method == "GET"
                    && route.path_template == "/users/{id}"
            })
            .expect("actix route");
        assert!(user
            .parameters
            .iter()
            .any(|parameter| parameter.name == "id" && parameter.location == "path"));
        assert!(routes.iter().any(|route| {
            route.framework == "actix-web"
                && route.http_method == "POST"
                && route.path_template == "/login"
        }));

        let rocket = r#"
use rocket::{get, post};

#[get("/health")]
fn health() {}

#[post("/items/<id>")]
fn create(id: usize) {}
"#;
        let tree = parser.parse(rocket, None).expect("tree");
        let (routes, _, _) = extract_routes("Rust", "src/routes.rs", rocket, tree.root_node());
        assert!(routes.iter().any(|route| {
            route.framework == "rocket"
                && route.http_method == "GET"
                && route.path_template == "/health"
        }));
        assert!(routes.iter().any(|route| {
            route.framework == "rocket"
                && route.http_method == "POST"
                && route.path_template == "/items/<id>"
        }));
    }

    #[test]
    fn axum_method_detection_does_not_match_handler_name_suffixes() {
        let source = r#"
use axum::{routing::post, Router};

async fn budget() {}

fn app() -> Router {
    Router::new().route("/budget", post(budget))
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _, _) = extract_routes("Rust", "src/main.rs", source, tree.root_node());
        assert!(!routes.iter().any(|route| route.http_method == "GET"));
        assert!(routes.iter().any(|route| {
            route.framework == "axum"
                && route.http_method == "POST"
                && route.path_template == "/budget"
        }));
    }

    #[test]
    fn extracts_axum_static_routes_and_method_router_chain() {
        let source = r#"
use axum::{routing::{get, post}, Router};

fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/users/{id}", get(show).post(update))
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _, _) = extract_routes("Rust", "src/main.rs", source, tree.root_node());
        assert!(routes.iter().any(|route| {
            route.framework == "axum"
                && route.http_method == "GET"
                && route.path_template == "/health"
        }));
        assert!(routes.iter().any(|route| {
            route.framework == "axum"
                && route.http_method == "GET"
                && route.path_template == "/users/{id}"
        }));
        assert!(routes.iter().any(|route| {
            route.framework == "axum"
                && route.http_method == "POST"
                && route.path_template == "/users/{id}"
        }));
    }

    #[test]
    fn extracts_fastapi_route_and_pydantic_body_fields() {
        let source = r#"
from fastapi import FastAPI, APIRouter, Query
from pydantic import BaseModel

app = FastAPI()
router = APIRouter(prefix="/api")

class LoginRequest(BaseModel):
    email: str
    password: str

@router.post("/login/{tenant}")
async def login(tenant: str, payload: LoginRequest, next: str = Query("")):
    return {"ok": True}

app.include_router(router)
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let (routes, _mounts, _handler_inputs) = extract_routes("Python", "app.py", source, tree.root_node());
        let route = routes.iter().find(|value| value.path_template == "/api/login/{tenant}").expect("route");
        assert_eq!(route.http_method, "POST");
        assert!(route.parameters.iter().any(|value| value.name == "tenant" && value.location == "path"));
        assert!(route.parameters.iter().any(|value| value.name == "email" && value.location == "json"));
        assert!(route.parameters.iter().any(|value| value.name == "password" && value.location == "json"));
        assert!(route.parameters.iter().any(|value| value.name == "next" && value.location == "query"));
    }
}
