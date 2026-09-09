use std::{collections::BTreeMap, fs};

use source_indexer::{index_project, IndexedFile, ParseState};
use tempfile::tempdir;

fn assert_symbol(file: &IndexedFile, kind: &str, name: &str) {
    assert!(
        file.symbols
            .iter()
            .any(|symbol| symbol.kind == kind && symbol.name == name),
        "missing {kind} symbol {name}: {:?}",
        file.symbols
    );
}

#[test]
fn covers_common_typescript_definition_forms() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("definitions.ts"),
        r#"
function localFunction(): number { return 0; }
export function exportedFunction(): number { return 1; }
async function asyncFunction(): Promise<number> { return 2; }
function* generatedFunction() { yield 3; }
class LocalService {
    localMethod(): void {}
}
export class ExportedService {
    exportedMethod(): void {}
}
export interface Config { enabled: boolean; }
export type Result = { ok: boolean };
const localArrow = (value: number) => value + 1;
const localFunctionExpression = function () { return 4; };
"#,
    )
    .expect("write TypeScript fixture");

    let result = index_project(dir.path(), &BTreeMap::new()).expect("index TypeScript fixture");
    assert_eq!(result.indexed_files.len(), 1);
    let file = &result.indexed_files[0];
    assert_eq!(file.parse_state, ParseState::Parsed);

    assert_symbol(file, "function", "localFunction");
    assert_symbol(file, "function", "exportedFunction");
    assert_symbol(file, "function", "asyncFunction");
    assert_symbol(file, "function", "generatedFunction");
    assert_symbol(file, "class", "LocalService");
    assert_symbol(file, "method", "localMethod");
    assert_symbol(file, "class", "ExportedService");
    assert_symbol(file, "method", "exportedMethod");
    assert_symbol(file, "interface", "Config");
    assert_symbol(file, "type", "Result");
    assert_symbol(file, "function", "localArrow");
    assert_symbol(file, "function", "localFunctionExpression");
}

#[test]
fn applies_definition_query_to_tsx_without_regex_fallbacks() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("component.tsx"),
        r#"
export interface Props { label: string; }
function helper(): string { return "ok"; }
export const Button = (props: Props) => <button>{props.label}</button>;
export class View {
    render(): JSX.Element { return <Button label={helper()} />; }
}
"#,
    )
    .expect("write TSX fixture");

    let result = index_project(dir.path(), &BTreeMap::new()).expect("index TSX fixture");
    assert_eq!(result.indexed_files.len(), 1);
    let file = &result.indexed_files[0];
    assert_eq!(file.parse_state, ParseState::Parsed);

    assert_symbol(file, "interface", "Props");
    assert_symbol(file, "function", "helper");
    assert_symbol(file, "function", "Button");
    assert_symbol(file, "class", "View");
    assert_symbol(file, "method", "render");
}
