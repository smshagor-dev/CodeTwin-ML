use std::collections::BTreeMap;

use tree_sitter::Node;

use crate::{IndexedRoute, IndexedRouteMount, IndexedRouteParameter};

const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "options", "head"];

pub fn extract_routes(
    language: &str,
    source: &str,
    root: Node<'_>,
) -> (Vec<IndexedRoute>, Vec<IndexedRouteMount>) {
    let (mut routes, mut mounts) = match language {
        "JavaScript" | "TypeScript" | "TypeScript TSX" => extract_express_routes(source, root),
        "Python" => extract_fastapi_routes(source, root),
        _ => (Vec::new(), Vec::new()),
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
    (routes, mounts)
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

        let handler_arg = arguments.named_child(1);
        let handler_name = handler_arg.and_then(|value| {
            if value.kind() == "identifier" {
                text(source, value).map(ToString::to_string)
            } else {
                None
            }
        });
        let handler_node = handler_arg
            .filter(|node| is_function_like(*node))
            .or_else(|| {
                handler_name
                    .as_ref()
                    .and_then(|name| handlers.get(name).copied())
            });

        let full_path = combine_paths(prefixes.get(&router).map(String::as_str), &path);
        let mut parameters = path_parameters(&full_path);
        if let Some(handler) = handler_node {
            parameters.extend(express_handler_parameters(source, handler));
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

fn keyword_string(value: &str, keyword: &str) -> Option<String> {
    let marker = format!("{keyword}=");
    let index = value.find(&marker)?;
    first_quoted_string(&value[index + marker.len()..])
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
                .split(':')
                .next()
                .unwrap_or("")
                .trim();
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
        let (routes, _mounts) = extract_routes("JavaScript", source, tree.root_node());
        let route = routes.iter().find(|value| value.path_template == "/api/login/:tenant").expect("route");
        assert_eq!(route.http_method, "POST");
        assert!(route.parameters.iter().any(|value| value.name == "tenant" && value.location == "path"));
        assert!(route.parameters.iter().any(|value| value.name == "email" && value.location == "json"));
        assert!(route.parameters.iter().any(|value| value.name == "password" && value.location == "json"));
        assert!(route.parameters.iter().any(|value| value.name == "next" && value.location == "query"));
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
        let (_routes, mounts) = extract_routes("JavaScript", source, tree.root_node());
        let mount = mounts.iter().find(|value| value.mounted_binding == "authRouter").expect("mount");
        assert_eq!(mount.prefix, "/api/auth");
        assert_eq!(mount.framework, "express");
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
        let (routes, _mounts) = extract_routes("Python", source, tree.root_node());
        let route = routes.iter().find(|value| value.path_template == "/api/login/{tenant}").expect("route");
        assert_eq!(route.http_method, "POST");
        assert!(route.parameters.iter().any(|value| value.name == "tenant" && value.location == "path"));
        assert!(route.parameters.iter().any(|value| value.name == "email" && value.location == "json"));
        assert!(route.parameters.iter().any(|value| value.name == "password" && value.location == "json"));
        assert!(route.parameters.iter().any(|value| value.name == "next" && value.location == "query"));
    }
}
