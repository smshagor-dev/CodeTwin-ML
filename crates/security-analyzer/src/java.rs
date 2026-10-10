//! Java source rules with intra-procedural taint tracking.
//!
//! Sources are servlet request accessors (`getParameter`, `getHeader`, `getCookies`, …) and
//! Spring MVC / JAX-RS parameters annotated as request input (`@RequestParam`, `@PathVariable`,
//! `@QueryParam`, …). Within each method, taint flows through assignments, `+=`, arrays,
//! enhanced `for` loops, collection and builder writes (`add`, `put`, `append`), and map reads
//! with literal keys. Helper methods in the same file are summarised: a call is tainted only if
//! the helper can return something derived from its parameters. Numeric parsing removes taint;
//! HTML escaping removes it for XSS sinks only.
//!
//! The analysis is flow-insensitive within a method (a variable tainted on any path stays
//! tainted), so it over-approximates. Sink rules that do not depend on taint (weak crypto, TLS,
//! CSRF, XXE, deserialization) match concrete API shapes.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use tree_sitter::Node;

use crate::{observation, SecurityObservation};

const REQUEST_ACCESSORS: &[&str] = &[
    "getparameter",
    "getparametervalues",
    "getparametermap",
    "getparameternames",
    "getheader",
    "getheaders",
    "getheadernames",
    "getquerystring",
    "getcookies",
    "getpathinfo",
    "getrequesturi",
    "getrequesturl",
];

const SOURCE_ANNOTATIONS: &[&str] = &[
    "requestparam",
    "pathvariable",
    "requestbody",
    "requestheader",
    "cookievalue",
    "modelattribute",
    "requestpart",
    "matrixvariable",
    "queryparam",
    "pathparam",
    "formparam",
    "headerparam",
    "cookieparam",
];

const SQL_SINKS: &[&str] = &[
    "executequery",
    "executeupdate",
    "executelargeupdate",
    "execute",
    "addbatch",
    "preparestatement",
    "preparecall",
    "createquery",
    "createnativequery",
    "createsqlquery",
    "query",
    "queryforobject",
    "queryforlist",
    "queryformap",
    "queryforrowset",
    "queryforint",
    "queryforlong",
    "update",
    "batchupdate",
];

const SQL_KEYWORDS: &[&str] = &[
    "select ", "insert ", "update ", "delete ", " where ", " from ", "order by", " values",
    "drop ", "{call", "call ",
];

const NUMERIC_PARSERS: &[&str] = &[
    "parseint",
    "parselong",
    "parseshort",
    "parsedouble",
    "parsefloat",
    "parseboolean",
];

const HTML_ESCAPERS: &[&str] = &[
    "encodeforhtml",
    "encodeforhtmlattribute",
    "encodeforjavascript",
    "encodeforxml",
    "encodeforxmlattribute",
    "htmlescape",
    "escapehtml",
    "escapehtml4",
    "escapehtml3",
    "escapexml",
    "escapexml10",
    "escapexml11",
    "escapeecmascript",
    "forhtml",
    "forhtmlcontent",
    "forhtmlattribute",
];

const URL_FETCHES: &[&str] = &["openconnection", "openstream", "getcontent"];

const COLLECTION_WRITES: &[&str] = &[
    "add",
    "addall",
    "put",
    "putall",
    "append",
    "insert",
    "set",
    "push",
    "offer",
    "addelement",
    "addfirst",
    "addlast",
    "setproperty",
];

/// Hardening calls that, when present anywhere in the file, show the XML parser was configured
/// against external entities.
const XML_HARDENING: &[&str] = &[
    "disallow-doctype-decl",
    "feature_secure_processing",
    "access_external_dtd",
    "access_external_schema",
    "is_supporting_external_entities",
    "issupportingexternalentities",
    "support_dtd",
    "supportdtd",
    "external-general-entities",
    "setexpandentityreferences(false)",
];

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or_default()
}

fn lower(node: Node<'_>, source: &str) -> String {
    text(node, source).to_ascii_lowercase()
}

fn compact(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !child.kind().ends_with("comment"))
        .collect()
}

fn arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
}

fn is_literal(node: Node<'_>) -> bool {
    matches!(node.kind(), "string_literal" | "text_block")
}

fn is_constant(node: Node<'_>) -> bool {
    is_literal(node)
        || matches!(
            node.kind(),
            "decimal_integer_literal"
                | "hex_integer_literal"
                | "decimal_floating_point_literal"
                | "character_literal"
                | "true"
                | "false"
                | "null_literal"
        )
}

/// String built at runtime: `+` concatenation with a non-literal operand, `String.format`,
/// `.formatted(…)` or `.concat(…)`.
fn is_built_string(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "binary_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .map(|op| text(op, source))
                .unwrap_or_default();
            operator == "+" && has_non_literal_operand(node)
        }
        "method_invocation" => matches!(
            invocation_name(node, source).as_str(),
            "format" | "formatted" | "concat"
        ),
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|inner| is_built_string(inner, source)),
        _ => false,
    }
}

fn has_non_literal_operand(node: Node<'_>) -> bool {
    if node.kind() != "binary_expression" {
        return !is_constant(node);
    }
    ["left", "right"]
        .iter()
        .filter_map(|field| node.child_by_field_name(field))
        .any(has_non_literal_operand)
}

fn string_literals_lower(node: Node<'_>, source: &str, out: &mut String) {
    if is_literal(node) {
        out.push_str(&lower(node, source));
        out.push(' ');
        return;
    }
    for child in named_children(node) {
        string_literals_lower(child, source, out);
    }
}

fn looks_like_sql(node: Node<'_>, source: &str) -> bool {
    let mut literals = String::new();
    string_literals_lower(node, source, &mut literals);
    SQL_KEYWORDS
        .iter()
        .any(|keyword| literals.contains(keyword))
}

fn first_string_argument(node: Node<'_>, source: &str) -> Option<String> {
    arguments(node)
        .into_iter()
        .next()
        .filter(|argument| is_literal(*argument))
        .map(|argument| {
            text(argument, source)
                .trim_matches('"')
                .to_ascii_lowercase()
        })
}

fn invocation_name(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("name")
        .map(|name| lower(name, source))
        .unwrap_or_default()
}

fn invocation_object(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("object")
}

fn identifier_name(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "identifier").then(|| text(node, source).to_string())
}

// ---------------------------------------------------------------------------------------------
// Flow-sensitive taint state

#[derive(Debug, Clone, PartialEq)]
enum Const {
    Int(i64),
    Bool(bool),
    Char(char),
    Str(String),
}

#[derive(Default, Clone)]
struct Taint {
    tainted: BTreeSet<String>,
    /// Tainted names whose current value was HTML-escaped.
    html_safe: BTreeSet<String>,
    /// Local variable -> declared type (lower case, no whitespace).
    types: BTreeMap<String, String>,
    /// Local variable -> first initializer text (lower case, no whitespace).
    initializers: BTreeMap<String, String>,
    /// Variables currently holding SQL built at runtime.
    sql_strings: BTreeSet<String>,
    /// Map variable -> literal key -> tainted.
    map_keys: BTreeMap<String, BTreeMap<String, bool>>,
    /// List variable -> per-index taint, while every operation on it used literal indexes.
    lists: BTreeMap<String, Vec<bool>>,
    /// Locals with a value known at analysis time.
    consts: BTreeMap<String, Const>,
    /// A `return` in this method returned tainted data, and whether any such value was not
    /// HTML-escaped (used for summaries).
    returns_tainted: bool,
    returns_unescaped: bool,
}

impl Taint {
    /// State after two paths meet: tainted on either path stays tainted.
    fn join(&mut self, other: &Taint) {
        // HTML-safe after the join: safe on every path where the name is tainted.
        let mut html_safe: BTreeSet<String> = self
            .html_safe
            .iter()
            .filter(|name| other.html_safe.contains(*name) || !other.tainted.contains(*name))
            .cloned()
            .collect();
        html_safe.extend(
            other
                .html_safe
                .iter()
                .filter(|name| !self.tainted.contains(*name))
                .cloned(),
        );
        self.html_safe = html_safe;
        self.tainted.extend(other.tainted.iter().cloned());
        self.sql_strings.extend(other.sql_strings.iter().cloned());
        for (name, keys) in &other.map_keys {
            let entry = self.map_keys.entry(name.clone()).or_default();
            for (key, tainted) in keys {
                *entry.entry(key.clone()).or_insert(false) |= *tainted;
            }
        }
        let names: BTreeSet<String> = self
            .lists
            .keys()
            .chain(other.lists.keys())
            .cloned()
            .collect();
        for name in names {
            match (self.lists.get(&name), other.lists.get(&name)) {
                (Some(a), Some(b)) if a.len() == b.len() => {
                    let merged = a.iter().zip(b).map(|(x, y)| *x || *y).collect();
                    self.lists.insert(name, merged);
                }
                _ => {
                    self.lists.remove(&name);
                }
            }
        }
        self.consts
            .retain(|name, value| other.consts.get(name) == Some(value));
        for (name, declared) in &other.types {
            self.types
                .entry(name.clone())
                .or_insert_with(|| declared.clone());
        }
        for (name, init) in &other.initializers {
            self.initializers
                .entry(name.clone())
                .or_insert_with(|| init.clone());
        }
        self.returns_tainted |= other.returns_tainted;
        self.returns_unescaped |= other.returns_unescaped;
    }

    fn taint(&mut self, name: &str, html_safe: bool) {
        self.tainted.insert(name.to_string());
        if html_safe {
            self.html_safe.insert(name.to_string());
        } else {
            self.html_safe.remove(name);
        }
    }

    fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
        self.html_safe.remove(name);
    }
}

/// What a same-file method can return, merged over overloads.
#[derive(Debug, Clone, Copy, Default)]
struct Summary {
    /// The return value can carry parameter taint.
    returns_parameter: bool,
    /// Every tainted value it returns was HTML-escaped.
    html_safe: bool,
}

type Summaries = BTreeMap<String, Summary>;

/// Same-file method (lower-case name, arity) -> which parameters receive tainted arguments.
type Seeds = BTreeMap<(String, usize), Vec<bool>>;

struct Context<'s> {
    source: &'s str,
    summaries: &'s Summaries,
    file_lower: &'s str,
    /// Parameters tainted at some call site in this file (input for this pass).
    seeds: &'s Seeds,
    /// Call-site taint observed during this pass.
    observed_seeds: std::cell::RefCell<Seeds>,
}

impl Context<'_> {
    fn is_request_source(&self, node: Node<'_>, name: &str) -> bool {
        REQUEST_ACCESSORS.contains(&name)
            && invocation_object(node).is_some_and(|object| {
                let object = lower(object, self.source);
                object.ends_with("request")
                    || object.ends_with("req")
                    || object.ends_with("getrequest()")
            })
    }

    /// A call to a method that may be defined in this file (no receiver, `this`, a new instance,
    /// or a receiver that is not a local variable).
    fn is_local_call(&self, node: Node<'_>, state: &Taint) -> bool {
        let source = self.source;
        invocation_object(node).is_none_or(|o| {
            matches!(o.kind(), "this" | "object_creation_expression")
                || identifier_name(o, source).is_some_and(|name| {
                    !state.tainted.contains(&name) && !state.types.contains_key(&name)
                })
        }) && self.summaries.contains_key(&invocation_name(node, source))
    }

    fn record_seed(&self, node: Node<'_>, state: &Taint) {
        if !self.is_local_call(node, state) {
            return;
        }
        let taints: Vec<bool> = arguments(node)
            .into_iter()
            .map(|arg| self.tainted(arg, state))
            .collect();
        if !taints.iter().any(|tainted| *tainted) {
            return;
        }
        let key = (invocation_name(node, self.source), taints.len());
        let mut seeds = self.observed_seeds.borrow_mut();
        let entry = seeds
            .entry(key)
            .or_insert_with(|| vec![false; taints.len()]);
        for (slot, tainted) in entry.iter_mut().zip(taints) {
            *slot |= tainted;
        }
    }

    fn const_value(&self, node: Node<'_>, state: &Taint) -> Option<Const> {
        let source = self.source;
        match node.kind() {
            "decimal_integer_literal" => text(node, source)
                .replace('_', "")
                .trim_end_matches(['l', 'L'])
                .parse()
                .ok()
                .map(Const::Int),
            "true" => Some(Const::Bool(true)),
            "false" => Some(Const::Bool(false)),
            "character_literal" => {
                let inner = text(node, source).trim_matches('\'');
                let mut chars = inner.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) => Some(Const::Char(c)),
                    _ => None,
                }
            }
            "string_literal" => {
                let raw = text(node, source);
                (!raw.contains('\\')).then(|| Const::Str(raw.trim_matches('"').to_string()))
            }
            "identifier" => state.consts.get(text(node, source)).cloned(),
            "parenthesized_expression" => node
                .named_child(0)
                .and_then(|inner| self.const_value(inner, state)),
            "unary_expression" => {
                let operator = node
                    .child_by_field_name("operator")
                    .map(|op| text(op, source))?;
                let operand = self.const_value(node.child_by_field_name("operand")?, state)?;
                match (operator, operand) {
                    ("!", Const::Bool(value)) => Some(Const::Bool(!value)),
                    ("-", Const::Int(value)) => Some(Const::Int(-value)),
                    _ => None,
                }
            }
            "binary_expression" => {
                let operator = node
                    .child_by_field_name("operator")
                    .map(|op| text(op, source))?;
                let left = self.const_value(node.child_by_field_name("left")?, state)?;
                let right = self.const_value(node.child_by_field_name("right")?, state)?;
                match (left, right) {
                    (Const::Int(a), Const::Int(b)) => match operator {
                        "+" => a.checked_add(b).map(Const::Int),
                        "-" => a.checked_sub(b).map(Const::Int),
                        "*" => a.checked_mul(b).map(Const::Int),
                        "/" if b != 0 => Some(Const::Int(a / b)),
                        "%" if b != 0 => Some(Const::Int(a % b)),
                        ">" => Some(Const::Bool(a > b)),
                        "<" => Some(Const::Bool(a < b)),
                        ">=" => Some(Const::Bool(a >= b)),
                        "<=" => Some(Const::Bool(a <= b)),
                        "==" => Some(Const::Bool(a == b)),
                        "!=" => Some(Const::Bool(a != b)),
                        _ => None,
                    },
                    (Const::Bool(a), Const::Bool(b)) => match operator {
                        "&&" => Some(Const::Bool(a && b)),
                        "||" => Some(Const::Bool(a || b)),
                        "==" => Some(Const::Bool(a == b)),
                        "!=" => Some(Const::Bool(a != b)),
                        _ => None,
                    },
                    (Const::Char(a), Const::Char(b)) => match operator {
                        "==" => Some(Const::Bool(a == b)),
                        "!=" => Some(Const::Bool(a != b)),
                        _ => None,
                    },
                    _ => None,
                }
            }
            "method_invocation" => {
                // "ABC".charAt(1) / guess.charAt(1) on a known string.
                let name = invocation_name(node, source);
                let object = self.const_value(invocation_object(node)?, state)?;
                let args = arguments(node);
                match (name.as_str(), object, args.as_slice()) {
                    ("charat", Const::Str(value), [index]) => {
                        match self.const_value(*index, state)? {
                            Const::Int(index) => usize::try_from(index)
                                .ok()
                                .and_then(|i| value.chars().nth(i))
                                .map(Const::Char),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn condition(&self, node: Option<Node<'_>>, state: &Taint) -> Option<bool> {
        match self.const_value(node?, state)? {
            Const::Bool(value) => Some(value),
            _ => None,
        }
    }

    fn tainted(&self, node: Node<'_>, state: &Taint) -> bool {
        let source = self.source;
        match node.kind() {
            "identifier" => state.tainted.contains(text(node, source)),
            "string_literal"
            | "text_block"
            | "character_literal"
            | "decimal_integer_literal"
            | "hex_integer_literal"
            | "decimal_floating_point_literal"
            | "true"
            | "false"
            | "null_literal"
            | "class_literal"
            | "lambda_expression" => false,
            "ternary_expression" => {
                let consequence = node.child_by_field_name("consequence");
                let alternative = node.child_by_field_name("alternative");
                match self.condition(node.child_by_field_name("condition"), state) {
                    Some(true) => consequence.is_some_and(|n| self.tainted(n, state)),
                    Some(false) => alternative.is_some_and(|n| self.tainted(n, state)),
                    None => {
                        consequence.is_some_and(|n| self.tainted(n, state))
                            || alternative.is_some_and(|n| self.tainted(n, state))
                    }
                }
            }
            "method_invocation" => {
                let name = invocation_name(node, source);
                if NUMERIC_PARSERS.contains(&name.as_str()) {
                    return false;
                }
                if self.is_request_source(node, &name) {
                    return true;
                }
                let object = invocation_object(node);
                let object_name = object.and_then(|o| identifier_name(o, source));
                let args = arguments(node);
                if let Some(target) = &object_name {
                    // Map read with a literal key whose value is known.
                    if name == "get" {
                        if let Some(key) = args.first().copied().filter(|arg| is_literal(*arg)) {
                            if let Some(value) = state
                                .map_keys
                                .get(target)
                                .and_then(|keys| keys.get(text(key, source)))
                            {
                                return *value;
                            }
                        }
                    }
                    // List read with a literal index while the list model is exact.
                    if matches!(name.as_str(), "get" | "remove") {
                        if let (Some(list), Some(Const::Int(index))) = (
                            state.lists.get(target),
                            args.first().and_then(|arg| self.const_value(*arg, state)),
                        ) {
                            if let Some(value) =
                                usize::try_from(index).ok().and_then(|i| list.get(i))
                            {
                                return *value;
                            }
                        }
                    }
                }
                let args_tainted = args.iter().any(|arg| self.tainted(*arg, state));
                // A helper defined in this file whose result never depends on its parameters.
                let local_helper = object.is_none_or(|o| {
                    matches!(o.kind(), "this" | "object_creation_expression")
                        || identifier_name(o, source).is_some_and(|name| {
                            !state.tainted.contains(&name) && !state.types.contains_key(&name)
                        })
                });
                if local_helper {
                    if let Some(summary) = self.summaries.get(&name) {
                        return summary.returns_parameter && args_tainted;
                    }
                }
                args_tainted || object.is_some_and(|o| self.tainted(o, state))
            }
            "object_creation_expression" => arguments(node)
                .into_iter()
                .any(|arg| self.tainted(arg, state)),
            _ => named_children(node)
                .into_iter()
                .any(|child| self.tainted(child, state)),
        }
    }

    fn html_safe(&self, node: Node<'_>, state: &Taint) -> bool {
        let source = self.source;
        match node.kind() {
            "identifier" => state.html_safe.contains(text(node, source)),
            "method_invocation" => {
                let name = invocation_name(node, source);
                HTML_ESCAPERS.contains(&name.as_str())
                    || self
                        .summaries
                        .get(&name)
                        .is_some_and(|summary| summary.html_safe)
                    || invocation_object(node).is_some_and(|object| self.html_safe(object, state))
            }
            "parenthesized_expression" | "cast_expression" => node
                .named_child(node.named_child_count().saturating_sub(1))
                .is_some_and(|inner| self.html_safe(inner, state)),
            "array_access" => node
                .child_by_field_name("array")
                .is_some_and(|array| self.html_safe(array, state)),
            // Arrays and concatenations are safe when every tainted part is.
            "array_initializer" | "array_creation_expression" | "binary_expression" => {
                let parts: Vec<Node<'_>> = if node.kind() == "array_creation_expression" {
                    node.child_by_field_name("value").into_iter().collect()
                } else {
                    named_children(node)
                };
                parts
                    .into_iter()
                    .all(|part| !self.tainted(part, state) || self.html_safe(part, state))
            }
            _ => false,
        }
    }

    /// `name = value`. A plain assignment replaces what `name` held.
    fn assign(&self, name: &str, value: Node<'_>, state: &mut Taint, strong: bool) {
        let tainted = self.tainted(value, state);
        let html_safe = tainted && self.html_safe(value, state);
        let built_sql = (is_built_string(value, self.source) && looks_like_sql(value, self.source))
            || identifier_name(value, self.source)
                .is_some_and(|other| state.sql_strings.contains(&other));
        let constant = self.const_value(value, state);
        let new_list = value.kind() == "object_creation_expression"
            && value
                .child_by_field_name("type")
                .is_some_and(|t| lower(t, self.source).contains("list"))
            && arguments(value).is_empty();
        if strong {
            state.clear(name);
            state.sql_strings.remove(name);
            state.map_keys.remove(name);
            state.lists.remove(name);
            state.consts.remove(name);
        }
        if tainted {
            state.taint(name, html_safe);
        }
        if built_sql {
            state.sql_strings.insert(name.to_string());
        }
        if strong {
            if let Some(constant) = constant {
                state.consts.insert(name.to_string(), constant);
            }
            if new_list {
                state.lists.insert(name.to_string(), Vec::new());
            }
        }
        state
            .initializers
            .entry(name.to_string())
            .or_insert_with(|| compact(&lower(value, self.source)));
    }

    /// Side effects of a call on a local collection or builder.
    fn apply_call(&self, node: Node<'_>, state: &mut Taint) {
        let source = self.source;
        let name = invocation_name(node, source);
        let Some(target) = invocation_object(node).and_then(|o| identifier_name(o, source)) else {
            return;
        };
        let args = arguments(node);
        let any_tainted = args.iter().any(|arg| self.tainted(*arg, state));
        if name == "put" && args.len() == 2 && is_literal(args[0]) {
            let value_tainted = self.tainted(args[1], state);
            state
                .map_keys
                .entry(target.clone())
                .or_default()
                .insert(text(args[0], source).to_string(), value_tainted);
        }
        if let Some(list) = state.lists.get(&target).cloned() {
            let index = |arg: Node<'_>| match self.const_value(arg, state) {
                Some(Const::Int(value)) => usize::try_from(value).ok(),
                _ => None,
            };
            let updated = match (name.as_str(), args.as_slice()) {
                ("add", [value]) => {
                    let mut list = list;
                    list.push(self.tainted(*value, state));
                    Some(list)
                }
                ("add", [position, value]) => {
                    index(*position).filter(|i| *i <= list.len()).map(|i| {
                        let mut list = list.clone();
                        list.insert(i, self.tainted(*value, state));
                        list
                    })
                }
                ("remove", [position]) => index(*position).filter(|i| *i < list.len()).map(|i| {
                    let mut list = list.clone();
                    list.remove(i);
                    list
                }),
                (
                    "get" | "size" | "isempty" | "contains" | "iterator" | "stream" | "foreach",
                    _,
                ) => Some(list),
                _ => None,
            };
            match updated {
                Some(list) => {
                    state.lists.insert(target.clone(), list);
                }
                None => {
                    state.lists.remove(&target);
                }
            }
        }
        if COLLECTION_WRITES.contains(&name.as_str()) && any_tainted {
            state.taint(&target, false);
        }
    }

    /// Runs `inspect` on every call and object creation in an expression, with the current
    /// state, without entering anonymous class bodies (their methods are analysed separately).
    fn scan_expression(
        &self,
        node: Node<'_>,
        state: &Taint,
        observations: &mut Vec<SecurityObservation>,
    ) {
        if node.kind() == "class_body" {
            return;
        }
        if node.kind() == "ternary_expression" {
            if let Some(condition) = node.child_by_field_name("condition") {
                self.scan_expression(condition, state, observations);
            }
            let branch = self.condition(node.child_by_field_name("condition"), state);
            if branch != Some(false) {
                if let Some(consequence) = node.child_by_field_name("consequence") {
                    self.scan_expression(consequence, state, observations);
                }
            }
            if branch != Some(true) {
                if let Some(alternative) = node.child_by_field_name("alternative") {
                    self.scan_expression(alternative, state, observations);
                }
            }
            return;
        }
        for child in named_children(node) {
            self.scan_expression(child, state, observations);
        }
        match node.kind() {
            "method_invocation" => {
                self.record_seed(node, state);
                inspect_invocation(node, self, state, self.file_lower, observations)
            }
            "object_creation_expression" => {
                inspect_creation(node, self, state, self.file_lower, observations)
            }
            _ => {}
        }
    }

    /// Applies an expression's effects (assignments, collection writes) in evaluation order.
    fn apply_expression(&self, node: Node<'_>, state: &mut Taint) {
        let source = self.source;
        match node.kind() {
            "class_body" | "lambda_expression" => return,
            "assignment_expression" => {
                if let Some(right) = node.child_by_field_name("right") {
                    self.apply_expression(right, state);
                }
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return;
                };
                let operator = node
                    .child_by_field_name("operator")
                    .map(|op| text(op, source))
                    .unwrap_or("=");
                match left.kind() {
                    "identifier" => {
                        let name = text(left, source).to_string();
                        if operator == "=" {
                            self.assign(&name, right, state, true);
                        } else {
                            // `+=` and friends keep what was there.
                            self.assign(&name, right, state, false);
                            state.consts.remove(&name);
                        }
                    }
                    "array_access" => {
                        if let Some(array) = left
                            .child_by_field_name("array")
                            .and_then(|a| identifier_name(a, source))
                        {
                            self.assign(&array, right, state, false);
                        }
                    }
                    "field_access" => {
                        if let Some(field) = left.child_by_field_name("field") {
                            self.assign(text(field, source), right, state, false);
                        }
                    }
                    _ => {}
                }
                return;
            }
            _ => {}
        }
        for child in named_children(node) {
            self.apply_expression(child, state);
        }
        if node.kind() == "method_invocation" {
            self.apply_call(node, state);
        }
    }

    fn expression(
        &self,
        node: Node<'_>,
        state: &mut Taint,
        observations: &mut Vec<SecurityObservation>,
    ) {
        self.scan_expression(node, state, observations);
        self.apply_expression(node, state);
    }

    fn declare(
        &self,
        node: Node<'_>,
        state: &mut Taint,
        observations: &mut Vec<SecurityObservation>,
    ) {
        let source = self.source;
        let declared = node
            .child_by_field_name("type")
            .map(|t| compact(&lower(t, source)))
            .unwrap_or_default();
        for declarator in named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "variable_declarator")
        {
            let Some(name) = declarator
                .child_by_field_name("name")
                .map(|n| text(n, source).to_string())
            else {
                continue;
            };
            state.types.insert(name.clone(), declared.clone());
            match declarator.child_by_field_name("value") {
                Some(value) => {
                    self.scan_expression(value, state, observations);
                    self.apply_expression(value, state);
                    self.assign(&name, value, state, true);
                }
                None => {
                    state.clear(&name);
                    state.consts.remove(&name);
                }
            }
        }
    }

    /// Executes one statement, reporting sinks with the state that holds at that point.
    fn statement(
        &self,
        node: Node<'_>,
        state: &mut Taint,
        observations: &mut Vec<SecurityObservation>,
    ) {
        let source = self.source;
        match node.kind() {
            "block" | "constructor_body" | "switch_block_statement_group" => {
                for child in named_children(node) {
                    self.statement(child, state, observations);
                }
            }
            "local_variable_declaration" => self.declare(node, state, observations),
            "expression_statement" => {
                for child in named_children(node) {
                    self.expression(child, state, observations);
                }
            }
            "return_statement" => {
                if let Some(value) = node.named_child(0) {
                    self.expression(value, state, observations);
                    if self.tainted(value, state) {
                        state.returns_tainted = true;
                        state.returns_unescaped |= !self.html_safe(value, state);
                    }
                }
            }
            "if_statement" => {
                let condition = node.child_by_field_name("condition");
                if let Some(condition) = condition {
                    self.expression(condition, state, observations);
                }
                let consequence = node.child_by_field_name("consequence");
                let alternative = node.child_by_field_name("alternative");
                match self.condition(condition, state) {
                    Some(true) => {
                        if let Some(branch) = consequence {
                            self.statement(branch, state, observations);
                        }
                    }
                    Some(false) => {
                        if let Some(branch) = alternative {
                            self.statement(branch, state, observations);
                        }
                    }
                    None => {
                        let mut otherwise = state.clone();
                        if let Some(branch) = consequence {
                            self.statement(branch, state, observations);
                        }
                        if let Some(branch) = alternative {
                            self.statement(branch, &mut otherwise, observations);
                        }
                        state.join(&otherwise);
                    }
                }
            }
            "while_statement" | "do_statement" | "for_statement" | "enhanced_for_statement" => {
                if node.kind() == "for_statement" {
                    for init in named_children(node)
                        .into_iter()
                        .filter(|c| c.kind() == "local_variable_declaration")
                    {
                        self.declare(init, state, observations);
                    }
                }
                if node.kind() == "enhanced_for_statement" {
                    if let (Some(name), Some(value)) = (
                        node.child_by_field_name("name"),
                        node.child_by_field_name("value"),
                    ) {
                        self.scan_expression(value, state, observations);
                        let name = text(name, source).to_string();
                        if self.tainted(value, state) {
                            state.taint(&name, false);
                        } else {
                            state.clear(&name);
                        }
                    }
                }
                // Twice: enough for values carried from one iteration into the next.
                let before = state.clone();
                for _ in 0..2 {
                    if let Some(condition) = node.child_by_field_name("condition") {
                        self.expression(condition, state, observations);
                    }
                    if let Some(body) = node.child_by_field_name("body") {
                        self.statement(body, state, observations);
                    }
                    for update in named_children(node)
                        .into_iter()
                        .filter(|_| node.kind() == "for_statement")
                    {
                        if update.kind().ends_with("expression")
                            && Some(update) != node.child_by_field_name("condition")
                        {
                            self.apply_expression(update, state);
                        }
                    }
                }
                state.join(&before);
            }
            "switch_expression" | "switch_statement" => {
                let condition = node.child_by_field_name("condition");
                if let Some(condition) = condition {
                    self.expression(condition, state, observations);
                }
                let value = condition.and_then(|c| self.const_value(c, state));
                let Some(body) = node.child_by_field_name("body") else {
                    return;
                };
                let groups = named_children(body);
                let matches = |group: Node<'_>, state: &Taint| -> Option<bool> {
                    let labels: Vec<Node<'_>> = named_children(group)
                        .into_iter()
                        .filter(|c| c.kind() == "switch_label")
                        .collect();
                    let value = value.as_ref()?;
                    // `default` groups are chosen separately when no case matches.
                    Some(labels.into_iter().any(|label| {
                        named_children(label)
                            .into_iter()
                            .any(|case| self.const_value(case, state).as_ref() == Some(value))
                    }))
                };
                let breaks = |group: Node<'_>| {
                    named_children(group).into_iter().any(|c| {
                        matches!(
                            c.kind(),
                            "break_statement" | "return_statement" | "throw_statement"
                        )
                    }) || group.kind() == "switch_rule"
                };
                if value.is_some() {
                    // Known selector: run the matching group (or default) and fall through.
                    let start = groups
                        .iter()
                        .position(|group| matches(*group, state) == Some(true))
                        .or_else(|| {
                            groups.iter().position(|group| {
                                lower(*group, source).trim_start().starts_with("default")
                            })
                        });
                    if let Some(start) = start {
                        for group in &groups[start..] {
                            self.switch_group(*group, state, observations);
                            if breaks(*group) {
                                break;
                            }
                        }
                    }
                } else {
                    let before = state.clone();
                    let mut merged = state.clone();
                    for group in &groups {
                        let mut branch = before.clone();
                        self.switch_group(*group, &mut branch, observations);
                        merged.join(&branch);
                    }
                    *state = merged;
                }
            }
            "try_statement" | "try_with_resources_statement" => {
                if let Some(resources) = node.child_by_field_name("resources") {
                    for resource in named_children(resources) {
                        if let (Some(name), Some(value)) = (
                            resource.child_by_field_name("name"),
                            resource.child_by_field_name("value"),
                        ) {
                            self.expression(value, state, observations);
                            self.assign(text(name, source), value, state, true);
                        }
                    }
                }
                let before = state.clone();
                if let Some(body) = node.child_by_field_name("body") {
                    self.statement(body, state, observations);
                }
                state.join(&before);
                let after_body = state.clone();
                for clause in named_children(node) {
                    match clause.kind() {
                        "catch_clause" => {
                            let mut branch = after_body.clone();
                            if let Some(body) = clause.child_by_field_name("body") {
                                self.statement(body, &mut branch, observations);
                            }
                            state.join(&branch);
                        }
                        "finally_clause" => {
                            for child in named_children(clause) {
                                self.statement(child, state, observations);
                            }
                        }
                        _ => {}
                    }
                }
            }
            "labeled_statement" | "synchronized_statement" => {
                for child in named_children(node) {
                    self.statement(child, state, observations);
                }
            }
            "throw_statement" | "yield_statement" | "assert_statement" => {
                for child in named_children(node) {
                    self.expression(child, state, observations);
                }
            }
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration" => {}
            kind if kind.ends_with("comment") => {}
            _ => {
                // Unknown statement: still report sinks inside it.
                self.scan_expression(node, state, observations);
            }
        }
    }

    fn switch_group(
        &self,
        group: Node<'_>,
        state: &mut Taint,
        observations: &mut Vec<SecurityObservation>,
    ) {
        for child in named_children(group) {
            if child.kind() != "switch_label" {
                self.statement(child, state, observations);
            }
        }
    }

    /// Analyses one method or constructor. Annotated request parameters are sources (every
    /// parameter when summarising).
    fn method(
        &self,
        method: Node<'_>,
        taint_all_parameters: bool,
        observations: &mut Vec<SecurityObservation>,
    ) -> Taint {
        let source = self.source;
        let mut state = Taint::default();
        if let Some(parameters) = method.child_by_field_name("parameters") {
            for parameter in named_children(parameters) {
                let Some(name) = parameter
                    .child_by_field_name("name")
                    .map(|n| text(n, source).to_string())
                else {
                    continue;
                };
                let declared = parameter
                    .child_by_field_name("type")
                    .map(|t| compact(&lower(t, source)))
                    .unwrap_or_default();
                state.types.insert(name.clone(), declared);
                let annotated = named_children(parameter)
                    .into_iter()
                    .filter(|child| child.kind() == "modifiers")
                    .any(|modifiers| {
                        let modifiers = lower(modifiers, source);
                        SOURCE_ANNOTATIONS
                            .iter()
                            .any(|annotation| modifiers.contains(&format!("@{annotation}")))
                    });
                let index = named_children(parameters)
                    .iter()
                    .position(|other| other.id() == parameter.id())
                    .unwrap_or(0);
                let seeded = method
                    .child_by_field_name("name")
                    .map(|n| lower(n, source))
                    .and_then(|name| self.seeds.get(&(name, named_children(parameters).len())))
                    .and_then(|slots| slots.get(index).copied())
                    .unwrap_or(false);
                if annotated || seeded || taint_all_parameters {
                    state.taint(&name, false);
                }
            }
        }
        if let Some(body) = method.child_by_field_name("body") {
            self.statement(body, &mut state, observations);
        }
        state
    }
}

fn collect_methods<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if node.kind() == "method_declaration" {
        out.push(node);
    }
    for child in named_children(node) {
        collect_methods(child, out);
    }
}

/// Which same-file methods can return parameter-derived data. Two rounds so helpers that call
/// other helpers settle.
fn summarize(root: Node<'_>, source: &str, file_lower: &str) -> Summaries {
    let mut methods = Vec::new();
    collect_methods(root, &mut methods);
    let mut summaries = Summaries::new();
    for _ in 0..2 {
        let mut next = Summaries::new();
        let context = Context {
            source,
            summaries: &summaries,
            file_lower,
            seeds: &Seeds::new(),
            observed_seeds: Default::default(),
        };
        for method in &methods {
            let Some(name) = method.child_by_field_name("name").map(|n| lower(n, source)) else {
                continue;
            };
            let has_parameters = method
                .child_by_field_name("parameters")
                .is_some_and(|parameters| parameters.named_child_count() > 0);
            let mut discarded = Vec::new();
            let state = context.method(*method, true, &mut discarded);
            let returns_parameter = has_parameters && state.returns_tainted;
            let entry = next.entry(name).or_insert(Summary {
                returns_parameter: false,
                html_safe: true,
            });
            entry.returns_parameter |= returns_parameter;
            entry.html_safe &= !returns_parameter || !state.returns_unescaped;
        }
        summaries = next;
    }
    summaries
}

// ---------------------------------------------------------------------------------------------
// Entry point

pub(crate) fn analyze(root: Node<'_>, source: &str, observations: &mut Vec<SecurityObservation>) {
    let file_lower = source.to_ascii_lowercase();
    let summaries = summarize(root, source, &file_lower);
    let seeds = seed_parameters(root, source, &file_lower, &summaries);
    let context = Context {
        source,
        summaries: &summaries,
        file_lower: &file_lower,
        seeds: &seeds,
        observed_seeds: Default::default(),
    };
    walk(root, &context, false, observations);
}

/// Taint that reaches same-file methods through their call sites: analyse every method, record
/// which arguments are tainted at local calls, and repeat with those parameters as sources
/// until nothing new is seeded.
fn seed_parameters(root: Node<'_>, source: &str, file_lower: &str, summaries: &Summaries) -> Seeds {
    let mut methods = Vec::new();
    collect_callables(root, &mut methods);
    let mut seeds = Seeds::new();
    for _ in 0..3 {
        let context = Context {
            source,
            summaries,
            file_lower,
            seeds: &seeds,
            observed_seeds: Default::default(),
        };
        for method in &methods {
            let mut discarded = Vec::new();
            context.method(*method, false, &mut discarded);
        }
        let observed = context.observed_seeds.into_inner();
        let mut next = seeds.clone();
        for (key, slots) in observed {
            let entry = next.entry(key).or_insert_with(|| vec![false; slots.len()]);
            for (slot, tainted) in entry.iter_mut().zip(slots) {
                *slot |= tainted;
            }
        }
        if next == seeds {
            break;
        }
        seeds = next;
    }
    seeds
}

fn collect_callables<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if matches!(
        node.kind(),
        "method_declaration" | "constructor_declaration"
    ) {
        out.push(node);
    }
    for child in named_children(node) {
        collect_callables(child, out);
    }
}

/// Methods and constructors get flow-sensitive analysis; code outside them (field initializers,
/// static blocks) is checked with an empty state. Nested and anonymous classes are reached
/// through their own class bodies.
fn walk(
    node: Node<'_>,
    context: &Context<'_>,
    inside_method: bool,
    observations: &mut Vec<SecurityObservation>,
) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" => {
            inspect_declaration(node, context.source, observations);
            context.method(node, false, observations);
            for child in named_children(node) {
                walk(child, context, true, observations);
            }
        }
        "class_body" | "interface_body" | "enum_body" => {
            for child in named_children(node) {
                walk(child, context, false, observations);
            }
        }
        "static_initializer" if !inside_method => {
            let mut state = Taint::default();
            for child in named_children(node) {
                context.statement(child, &mut state, observations);
            }
            for child in named_children(node) {
                walk(child, context, true, observations);
            }
        }
        _ => {
            if !inside_method {
                match node.kind() {
                    "method_invocation" => inspect_invocation(
                        node,
                        context,
                        &Taint::default(),
                        context.file_lower,
                        observations,
                    ),
                    "object_creation_expression" => inspect_creation(
                        node,
                        context,
                        &Taint::default(),
                        context.file_lower,
                        observations,
                    ),
                    _ => {}
                }
            }
            for child in named_children(node) {
                walk(child, context, inside_method, observations);
            }
        }
    }
}

fn declared_type<'a>(object: Option<Node<'_>>, source: &str, state: &'a Taint) -> &'a str {
    object
        .and_then(|o| identifier_name(o, source))
        .and_then(|name| state.types.get(&name))
        .map_or("", String::as_str)
}

fn initializer<'a>(object: Option<Node<'_>>, source: &str, state: &'a Taint) -> &'a str {
    object
        .and_then(|o| identifier_name(o, source))
        .and_then(|name| state.initializers.get(&name))
        .map_or("", String::as_str)
}

fn inspect_invocation(
    node: Node<'_>,
    context: &Context<'_>,
    state: &Taint,
    file_lower: &str,
    observations: &mut Vec<SecurityObservation>,
) {
    let source = context.source;
    let name = invocation_name(node, source);
    let object_node = invocation_object(node);
    let object = object_node
        .map(|object| compact(&lower(object, source)))
        .unwrap_or_default();
    let object_type = declared_type(object_node, source, state);
    let object_init = initializer(object_node, source, state);
    let callee = if object.is_empty() {
        name.clone()
    } else {
        format!("{object}.{name}")
    };
    let args = arguments(node);
    let first = args.first().copied();
    let any_tainted = args.iter().any(|arg| context.tainted(*arg, state));

    // SQL text assembled at runtime.
    if SQL_SINKS.contains(&name.as_str()) {
        if let Some(query) = first {
            let built = (is_built_string(query, source) && looks_like_sql(query, source))
                || identifier_name(query, source)
                    .is_some_and(|var| state.sql_strings.contains(&var));
            if built && context.tainted(query, state) {
                observations.push(observation(
                    "web.sql.request_to_query",
                    "critical",
                    0.95,
                    "Request-controlled data reaches a SQL query string",
                    "Request input is concatenated or formatted into SQL text passed to a JDBC/JPA/Spring query API. Use a PreparedStatement or named parameters and bind every value; map dynamic identifiers through a fixed allow-list.",
                    "CWE-89",
                    Some("OWASP A03:2021 Injection"),
                    node,
                    callee.clone(),
                    format!("Request input is built into SQL passed to `{callee}`."),
                    json!({"callee": callee, "request_controlled": true, "language": "java"}),
                ));
            } else if built {
                observations.push(observation(
                    "java.sql.concatenated_query",
                    "high",
                    0.70,
                    "SQL built by string concatenation or formatting",
                    "SQL text is assembled from non-literal values and passed to a query API. No request input was traced into it, but parameter binding (`?` / `:name`) removes the injection class entirely. Review where the concatenated values come from.",
                    "CWE-89",
                    Some("OWASP A03:2021 Injection"),
                    node,
                    callee.clone(),
                    format!("SQL passed to `{callee}` is built at runtime; bind values as parameters."),
                    json!({"callee": callee, "request_controlled": false, "review_required": true, "language": "java"}),
                ));
            }
        }
    }

    // Process execution.
    let runtime_exec = name == "exec"
        && (object.ends_with("getruntime()")
            || object_type.ends_with("runtime")
            || object_init.contains("getruntime()"));
    let builder_command = name == "command" && object_type.ends_with("processbuilder");
    if (runtime_exec || builder_command) && first.is_some_and(|argument| !is_literal(argument)) {
        let built = first.is_some_and(|argument| is_built_string(argument, source));
        push_command(node, &callee, any_tainted, built, observations);
    }

    // Weak digests.
    if name == "getinstance" && object.ends_with("messagedigest") {
        if let Some(algorithm) = first_string_argument(node, source) {
            if matches!(
                algorithm.as_str(),
                "md5" | "md2" | "md4" | "sha1" | "sha-1" | "sha"
            ) {
                push_weak_hash(node, &callee, &algorithm, observations);
            }
        }
    }
    if object.ends_with("digestutils")
        && matches!(
            name.as_str(),
            "md5" | "md5hex" | "md2" | "md2hex" | "sha1" | "sha1hex" | "sha" | "shahex"
        )
    {
        push_weak_hash(node, &callee, &name, observations);
    }

    // Weak ciphers and ECB mode.
    if name == "getinstance" && object.ends_with("cipher") {
        if let Some(transformation) = first_string_argument(node, source) {
            let upper = transformation.to_ascii_uppercase();
            let algorithm = upper.split('/').next().unwrap_or_default();
            let weak_algorithm = matches!(
                algorithm,
                "DES" | "DESEDE" | "TRIPLEDES" | "RC2" | "RC4" | "ARCFOUR" | "BLOWFISH"
            );
            // "AES" alone defaults to AES/ECB/PKCS5Padding in the JDK providers.
            let ecb = upper.contains("/ECB/") || upper == "AES";
            if weak_algorithm || ecb {
                observations.push(observation(
                    "java.crypto.weak_cipher",
                    "medium",
                    0.85,
                    "Weak cipher or ECB mode",
                    "The cipher transformation uses a broken or deprecated algorithm, or ECB mode, which leaks plaintext patterns. Use AES/GCM/NoPadding (or ChaCha20-Poly1305) with a unique nonce per message.",
                    "CWE-327",
                    Some("OWASP A02:2021 Cryptographic Failures"),
                    node,
                    callee.clone(),
                    format!("Cipher transformation `{transformation}` is weak or uses ECB."),
                    json!({"callee": callee, "transformation": transformation, "ecb": ecb, "language": "java"}),
                ));
            }
        }
    }

    // XML parser factories without external-entity hardening in the same file.
    if matches!(
        name.as_str(),
        "newinstance" | "newfactory" | "newdefaultinstance" | "newdefaultfactory"
    ) && [
        "documentbuilderfactory",
        "saxparserfactory",
        "xmlinputfactory",
        "transformerfactory",
        "schemafactory",
        "saxtransformerfactory",
    ]
    .iter()
    .any(|factory| object.ends_with(factory))
        && !XML_HARDENING
            .iter()
            .any(|marker| file_lower.contains(marker))
    {
        push_xxe(node, &callee, observations);
    }

    // TLS hostname verification disabled.
    if matches!(
        name.as_str(),
        "sethostnameverifier" | "setdefaulthostnameverifier" | "setsslhostnameverifier"
    ) {
        let argument = compact(
            &args
                .iter()
                .map(|arg| lower(*arg, source))
                .collect::<String>(),
        );
        if argument.contains("->true")
            || argument.contains("noophostnameverifier")
            || argument.contains("allow_all_hostname_verifier")
            || argument.contains("allowallhostnameverifier")
        {
            observations.push(observation(
                "java.tls.hostname_verification_disabled",
                "high",
                0.92,
                "TLS hostname verification disabled",
                "A hostname verifier that accepts every host lets anyone with any valid certificate impersonate the server. Remove the custom verifier and use the platform default.",
                "CWE-295",
                Some("OWASP A07:2021 Identification and Authentication Failures"),
                node,
                callee.clone(),
                format!("`{callee}` installs a verifier that accepts every hostname."),
                json!({"callee": callee, "language": "java"}),
            ));
        }
    }

    // Spring Security CSRF protection turned off.
    let csrf_disabled = (name == "disable" && object.ends_with("csrf()"))
        || (name == "csrf"
            && args
                .iter()
                .any(|arg| lower(*arg, source).contains("disable")));
    if csrf_disabled {
        observations.push(observation(
            "java.spring.csrf_disabled",
            "medium",
            0.60,
            "Spring Security CSRF protection disabled",
            "CSRF protection is switched off. That is reasonable for a stateless API authenticated only by bearer tokens, and dangerous for anything using cookies or sessions. Confirm which applies.",
            "CWE-352",
            Some("OWASP A01:2021 Broken Access Control"),
            node,
            callee.clone(),
            "CSRF protection is disabled in the Spring Security configuration.".into(),
            json!({"callee": callee, "review_required": true, "language": "java"}),
        ));
    }

    // Cookies sent over plain HTTP.
    if name == "setsecure" && first.is_some_and(|arg| text(arg, source) == "false") {
        observations.push(observation(
            "java.cookie.not_secure",
            "medium",
            0.80,
            "Cookie explicitly allowed over plain HTTP",
            "`setSecure(false)` lets the browser send this cookie without TLS, where it can be read or modified in transit. Set it to true for anything session- or identity-related.",
            "CWE-614",
            Some("OWASP A05:2021 Security Misconfiguration"),
            node,
            callee.clone(),
            format!("`{callee}(false)` disables the Secure flag."),
            json!({"callee": callee, "language": "java"}),
        ));
    }

    // ScriptEngine.eval / SpEL parseExpression with a non-literal.
    let script_eval =
        name == "eval" && (object.contains("engine") || object_type.contains("scriptengine"));
    let spel = name == "parseexpression";
    if (script_eval || spel) && first.is_some_and(|argument| !is_literal(argument)) {
        observations.push(observation(
            "security.dynamic_code_execution",
            if any_tainted { "critical" } else { "medium" },
            if any_tainted { 0.95 } else { 0.68 },
            "Dynamic code or expression evaluation",
            "A script engine or Spring Expression Language parser evaluates a non-literal string. If any part of it can come from a user, this is remote code execution. Keep expressions fixed or evaluate against a restricted context (SimpleEvaluationContext).",
            if spel { "CWE-917" } else { "CWE-95" },
            Some("OWASP A03:2021 Injection"),
            node,
            callee.clone(),
            format!("`{callee}` evaluates a runtime-built expression."),
            json!({"callee": callee, "request_controlled": any_tainted, "review_required": !any_tainted, "language": "java"}),
        ));
    }

    // Unsafe deserialization libraries.
    if name == "fromxml" && object.contains("xstream") {
        push_deserialization(node, &callee, "medium", 0.70, observations);
    }

    let url_fetch = URL_FETCHES.contains(&name.as_str())
        && object_type.ends_with("url")
        && object_node.is_some_and(|object| context.tainted(object, state));
    if url_fetch {
        push_ssrf(node, &callee, observations);
    }

    if !any_tainted {
        return;
    }

    // Response writers (reflected XSS). HTML-escaped values are safe here.
    let writer = object.ends_with("getwriter()")
        || object.ends_with("getoutputstream()")
        || object_init.contains("getwriter()")
        || object_init.contains("getoutputstream()");
    if writer
        && matches!(
            name.as_str(),
            "print" | "println" | "write" | "format" | "printf" | "append"
        )
        && args
            .iter()
            .any(|arg| context.tainted(*arg, state) && !context.html_safe(*arg, state))
    {
        observations.push(observation(
            "web.xss.request_to_response",
            "high",
            0.90,
            "Request-controlled data written to the HTTP response",
            "Request input is written to the response body without HTML encoding, which allows reflected cross-site scripting. Encode for the output context (e.g. OWASP Encoder `Encode.forHtml`) or render through an auto-escaping template.",
            "CWE-79",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.clone(),
            format!("Unencoded request input reaches `{callee}`."),
            json!({"callee": callee, "request_controlled": true, "language": "java"}),
        ));
    }

    if name == "sendredirect" {
        observations.push(observation(
            "web.redirect.request_to_location",
            "high",
            0.90,
            "Request-controlled redirect target",
            "A redirect location comes from the request. Allow only relative paths or an explicit list of destinations to prevent open redirects used in phishing.",
            "CWE-601",
            Some("OWASP A01:2021 Broken Access Control"),
            node,
            callee.clone(),
            format!("Request input reaches `{callee}`."),
            json!({"callee": callee, "request_controlled": true, "language": "java"}),
        ));
    }
    if matches!(name.as_str(), "setheader" | "addheader") && object.contains("response") {
        observations.push(observation(
            "web.header.request_to_response",
            "high",
            0.94,
            "Request-controlled value reaches an HTTP response header",
            "Reject carriage-return/line-feed characters and prefer fixed or allow-listed header values.",
            "CWE-113",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.clone(),
            format!("Request input reaches response-header call `{callee}`."),
            json!({"callee": callee, "request_controlled": true, "language": "java"}),
        ));
    }

    // LDAP search filters.
    let ldap_context = object_type.contains("dircontext")
        || object_type.contains("ldap")
        || object.contains("ctx")
        || object.contains("context");
    if name == "search" && args.len() >= 2 && ldap_context && context.tainted(args[1], state) {
        observations.push(observation(
            "web.ldap.request_to_filter",
            "high",
            0.88,
            "Request-controlled LDAP search filter",
            "Request input is built into an LDAP filter, which allows LDAP injection. Escape filter values (RFC 4515) or use a filter API with bound arguments such as `search(name, filterExpr, filterArgs, controls)`.",
            "CWE-90",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.clone(),
            format!("Request input reaches LDAP filter in `{callee}`."),
            json!({"callee": callee, "request_controlled": true, "language": "java"}),
        ));
    }

    // XPath expressions.
    let xpath = object_type.ends_with("xpath")
        || object.contains("xpath")
        || object_init.contains("newxpath()");
    if matches!(name.as_str(), "evaluate" | "compile")
        && xpath
        && first.is_some_and(|arg| context.tainted(arg, state))
    {
        observations.push(observation(
            "web.xpath.request_to_expression",
            "high",
            0.88,
            "Request-controlled XPath expression",
            "Request input is built into an XPath expression, which allows XPath injection. Use a fixed expression with variables supplied through an XPathVariableResolver.",
            "CWE-643",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.clone(),
            format!("Request input reaches XPath call `{callee}`."),
            json!({"callee": callee, "request_controlled": true, "language": "java"}),
        ));
    }

    // The URL is the first argument; a tainted request body alone is not SSRF.
    let outbound = (matches!(
        name.as_str(),
        "getforobject" | "getforentity" | "postforobject" | "postforentity" | "exchange"
    ) || (name == "create" && object == "uri")
        || (name == "uri" && object.contains("webclient")))
        && first.is_some_and(|url| context.tainted(url, state));
    if outbound {
        push_ssrf(node, &callee, observations);
    }
    let file_access = (name == "get" && object.ends_with("paths"))
        || (name == "of" && object.ends_with("path"))
        || (object.ends_with("files")
            && matches!(
                name.as_str(),
                "readallbytes"
                    | "readstring"
                    | "readalllines"
                    | "newinputstream"
                    | "newoutputstream"
                    | "newbufferedreader"
                    | "newbufferedwriter"
                    | "write"
                    | "writestring"
                    | "delete"
                    | "copy"
                    | "lines"
            ));
    if file_access {
        push_path(node, &callee, observations);
    }
}

fn inspect_creation(
    node: Node<'_>,
    context: &Context<'_>,
    state: &Taint,
    file_lower: &str,
    observations: &mut Vec<SecurityObservation>,
) {
    let source = context.source;
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_name = compact(&lower(type_node, source));
    let simple = type_name
        .rsplit('.')
        .next()
        .unwrap_or(&type_name)
        .split('<')
        .next()
        .unwrap_or_default()
        .to_string();
    let args = arguments(node);
    let tainted = args.iter().any(|arg| context.tainted(*arg, state));
    let callee = format!("new {simple}");

    match simple.as_str() {
        "objectinputstream" => push_deserialization(node, &callee, "high", 0.70, observations),
        "xmldecoder" => push_deserialization(node, &callee, "high", 0.80, observations),
        "processbuilder" => {
            if args.iter().any(|argument| !is_literal(*argument)) {
                push_command(node, &callee, tainted, false, observations);
            }
        }
        "saxbuilder" | "saxreader" => {
            if !XML_HARDENING
                .iter()
                .any(|marker| file_lower.contains(marker))
            {
                push_xxe(node, &callee, observations);
            }
        }
        // Only a URL that is actually fetched is SSRF; `new URL(x).getHost()` just parses.
        "url"
            if tainted
                && node.parent().is_some_and(|parent| {
                    parent.kind() == "method_invocation"
                        && invocation_object(parent).is_some_and(|object| object.id() == node.id())
                        && URL_FETCHES.contains(&invocation_name(parent, source).as_str())
                }) =>
        {
            push_ssrf(node, &callee, observations)
        }
        "file" | "fileinputstream" | "fileoutputstream" | "filereader" | "filewriter"
        | "randomaccessfile"
            if tainted =>
        {
            push_path(node, &callee, observations)
        }
        _ => {}
    }
}

/// An `X509TrustManager.checkServerTrusted` that does nothing trusts every certificate.
fn inspect_declaration(node: Node<'_>, source: &str, observations: &mut Vec<SecurityObservation>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if text(name, source) != "checkServerTrusted" {
        return;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    if named_children(body).is_empty() {
        observations.push(observation(
            "java.tls.trust_all_certificates",
            "high",
            0.90,
            "Trust manager accepts every certificate",
            "`checkServerTrusted` returns without checking anything, so TLS connections using this trust manager accept forged certificates. Remove the custom trust manager or validate the chain properly.",
            "CWE-295",
            Some("OWASP A07:2021 Identification and Authentication Failures"),
            node,
            "checkServerTrusted".into(),
            "An empty checkServerTrusted implementation disables certificate validation.".into(),
            json!({"language": "java"}),
        ));
    }
}

fn push_command(
    node: Node<'_>,
    callee: &str,
    request: bool,
    built_string: bool,
    observations: &mut Vec<SecurityObservation>,
) {
    if request {
        observations.push(observation(
            "web.command.request_to_process",
            "critical",
            0.95,
            "Request-controlled value reaches a process execution sink",
            "Do not pass request data to a process. Use a fixed executable and argument list with strict allow-list validation, or remove the execution path.",
            "CWE-78",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.to_string(),
            format!("Request input reaches process call `{callee}`."),
            json!({"callee": callee, "request_controlled": true, "language": "java"}),
        ));
        return;
    }
    observations.push(observation(
        "java.command.dynamic_exec",
        if built_string { "high" } else { "medium" },
        if built_string { 0.70 } else { 0.55 },
        "Process started with a runtime-built command",
        "A process is started with a non-literal command and no request input was traced into it. `Runtime.exec(String)` splits the string on whitespace, so concatenated input can add arguments. Pass a fixed executable and an explicit argument array, and validate every variable part.",
        "CWE-78",
        Some("OWASP A03:2021 Injection"),
        node,
        callee.to_string(),
        format!("`{callee}` runs a command assembled at runtime."),
        json!({"callee": callee, "request_controlled": false, "review_required": true, "language": "java"}),
    ));
}

fn push_weak_hash(
    node: Node<'_>,
    callee: &str,
    algorithm: &str,
    observations: &mut Vec<SecurityObservation>,
) {
    observations.push(observation(
        "security.weak_cryptographic_hash",
        "medium",
        0.82,
        "Weak cryptographic hash primitive",
        "MD5 and SHA-1 are collision-broken for signatures, integrity and password storage. Use SHA-256 or better, and a password hash (bcrypt, scrypt, Argon2, PBKDF2) for passwords. Checksum-only uses can be intentional.",
        "CWE-327",
        Some("OWASP A02:2021 Cryptographic Failures"),
        node,
        callee.to_string(),
        format!("Weak digest `{algorithm}` requested via `{callee}`."),
        json!({"callee": callee, "algorithm": algorithm, "review_required": true, "language": "java"}),
    ));
}

fn push_deserialization(
    node: Node<'_>,
    callee: &str,
    severity: &str,
    confidence: f64,
    observations: &mut Vec<SecurityObservation>,
) {
    observations.push(observation(
        "java.deserialization.untrusted_stream",
        severity,
        confidence,
        "Java object deserialization",
        "Native Java deserialization (ObjectInputStream, XMLDecoder, XStream) can execute code through gadget chains when the input is attacker-controlled. Prefer JSON with explicit types, or install an ObjectInputFilter allow-list.",
        "CWE-502",
        Some("OWASP A08:2021 Software and Data Integrity Failures"),
        node,
        callee.to_string(),
        format!("`{callee}` deserializes objects; the input source requires review."),
        json!({"callee": callee, "review_required": true, "language": "java"}),
    ));
}

fn push_xxe(node: Node<'_>, callee: &str, observations: &mut Vec<SecurityObservation>) {
    observations.push(observation(
        "java.xml.xxe_unhardened_parser",
        "medium",
        0.70,
        "XML parser created without external-entity hardening",
        "Java XML parsers resolve external entities by default in many configurations, which allows file disclosure and SSRF (XXE). Set `disallow-doctype-decl` to true or enable FEATURE_SECURE_PROCESSING and clear ACCESS_EXTERNAL_DTD/SCHEMA.",
        "CWE-611",
        Some("OWASP A05:2021 Security Misconfiguration"),
        node,
        callee.to_string(),
        format!("`{callee}` is used and no XXE hardening setting appears in this file."),
        json!({"callee": callee, "review_required": true, "language": "java"}),
    ));
}

fn push_ssrf(node: Node<'_>, callee: &str, observations: &mut Vec<SecurityObservation>) {
    observations.push(observation(
        "web.ssrf.request_url",
        "high",
        0.92,
        "Request-controlled URL reaches an outbound HTTP client",
        "Allow-list destination schemes and hosts and block private, loopback, link-local and metadata-service addresses before making outbound requests.",
        "CWE-918",
        Some("OWASP A10:2021 Server-Side Request Forgery"),
        node,
        callee.to_string(),
        format!("Request input reaches outbound call `{callee}`."),
        json!({"callee": callee, "request_controlled": true, "language": "java"}),
    ));
}

fn push_path(node: Node<'_>, callee: &str, observations: &mut Vec<SecurityObservation>) {
    observations.push(observation(
        "web.path.request_to_file",
        "high",
        0.90,
        "Request-controlled file path",
        "A file path is built from request input. Resolve it against a fixed base directory, normalize it, and reject results outside that directory (or map user choices to known file names).",
        "CWE-22",
        Some("OWASP A01:2021 Broken Access Control"),
        node,
        callee.to_string(),
        format!("Request input reaches file API `{callee}`."),
        json!({"callee": callee, "request_controlled": true, "language": "java"}),
    ));
}
