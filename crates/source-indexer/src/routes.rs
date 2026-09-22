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
            (routes, mounts, javascript_handler_inputs(source, root))
        }
        "Python" => {
            let (mut routes, mut mounts) = extract_fastapi_routes(source, root);
            let (flask_routes, flask_mounts) = extract_flask_routes(source, root);
            routes.extend(flask_routes);
            mounts.extend(flask_mounts);
            (routes, mounts, Vec::new())
        }
        "PHP" => {
            let (routes, mounts) = extract_laravel_routes(source, root);
            (routes, mounts, Vec::new())
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
    handler_inputs.dedup_by(|left, right| {
        left.handler_name == right.handler_name
            && left.start_line == right.start_line
            && left.end_line == right.end_line
    });
    (routes, mounts, handler_inputs)
}

fn extract_nextjs_app_routes(
    relative_path: &str,
    source: &str,
    root: Node<'_>,
) -> Vec<IndexedRoute> {
    let Some(path_template) = nextjs_app_route_path(relative_path) else {
        return Vec::new();
    };
    let mut routes = Vec::new();
    walk(root, &mut |node| {
        if node.kind() != "export_statement" {
            return;
        }
        let Some(value) = text(source, node) else {
            return;
        };
        let methods = nextjs_exported_http_methods(value);
        if methods.is_empty() {
            return;
        }
        let mut parameters = path_parameters(&path_template);
        normalize_parameters(&mut parameters);
        let start = node.start_position();
        let end = node.end_position();
        for method in methods {
            routes.push(IndexedRoute {
                framework: "nextjs".to_string(),
                router_name: "app_router".to_string(),
                router_prefix: String::new(),
                http_method: method.to_string(),
                path_template: path_template.clone(),
                handler_name: Some(method.to_string()),
                parameters: parameters.clone(),
                request_content_type: None,
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

fn nextjs_exported_http_methods(value: &str) -> Vec<&'static str> {
    const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut output = Vec::new();

    for method in METHODS {
        let function = format!("export function {method}(");
        let async_function = format!("export async function {method}(");
        let const_handler = format!("export const {method} =");
        let let_handler = format!("export let {method} =");
        let var_handler = format!("export var {method} =");
        if normalized.contains(&function)
            || normalized.contains(&async_function)
            || normalized.contains(&const_handler)
            || normalized.contains(&let_handler)
            || normalized.contains(&var_handler)
        {
            output.push(method);
        }
    }

    if let Some(open) = normalized.find('{') {
        if normalized.starts_with("export ") {
            if let Some(relative_close) = normalized[open + 1..].find('}') {
                let body = &normalized[open + 1..open + 1 + relative_close];
                for item in body.split(',') {
                    let item = item.trim();
                    if item.is_empty() {
                        continue;
                    }
                    let exported = item
                        .rsplit_once(" as ")
                        .map(|(_, exported)| exported.trim())
                        .unwrap_or(item);
                    for method in METHODS {
                        if exported == method && !output.contains(&method) {
                            output.push(method);
                        }
                    }
                }
            }
        }
    }

    output
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
) -> (Vec<IndexedRoute>, Vec<IndexedRouteMount>) {
    let (prefixes, mounts) = flask_router_prefixes(source, root);
    if prefixes.is_empty() {
        return (Vec::new(), mounts);
    }
    let mut routes = Vec::new();

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

        for decorator in named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "decorator")
        {
            let Some(raw) = text(source, decorator) else {
                continue;
            };
            let Some((router, methods, path)) =
                parse_flask_decorator(raw, &prefixes)
            else {
                continue;
            };
            let router_prefix = prefixes.get(&router).cloned().unwrap_or_default();
            let full_path = combine_paths(
                (!router_prefix.is_empty()).then_some(router_prefix.as_str()),
                &path,
            );
            let mut parameters = path_parameters(&full_path);
            normalize_parameters(&mut parameters);
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
                    request_content_type: None,
                    start_line: start.row + 1,
                    end_line: end.row + 1,
                });
            }
        }
    });

    (routes, mounts)
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
        if matches!(character, '"' | '\'') {
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
        if !matches!(character, '"' | '\'') {
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
    fn skips_nextjs_catch_all_route_materialization() {
        let source = "export function GET() { return new Response('ok'); }";
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
        assert!(!routes.iter().any(|route| route.framework == "nextjs"));
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
