//! Connect CodeTwin to the unmodified PentAGI Go backend through its public GraphQL API.
//! Credentials are read only by the Rust process, never returned to the WebView.
use reqwest::Url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

const MAX_OBJECTIVE_BYTES: usize = 2_000;
const MAX_LOG_ITEMS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentagiProvider {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentagiFlow {
    pub id: String,
    pub title: String,
    pub status: String,
    pub provider: PentagiProvider,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct PentagiConnection {
    pub configured: bool,
    pub connected: bool,
    pub detail: String,
    pub providers: Vec<PentagiProvider>,
}

#[derive(Debug, Deserialize)]
struct GraphResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphError>>,
}
#[derive(Debug, Deserialize)]
struct GraphError {
    message: String,
}

fn config() -> Result<(Url, String), String> {
    let raw = std::env::var("CODETWIN_PENTAGI_URL")
        .map_err(|_| "Set CODETWIN_PENTAGI_URL to your PentAGI Go server URL".to_string())?;
    let token = std::env::var("CODETWIN_PENTAGI_TOKEN")
        .map_err(|_| "Set CODETWIN_PENTAGI_TOKEN with a PentAGI API token".to_string())?;
    if token.trim().is_empty() {
        return Err("PentAGI API token must not be empty".into());
    }
    let url = Url::parse(&raw).map_err(|_| "Invalid PentAGI server URL".to_string())?;
    if url.username() != "" || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err("PentAGI URL must not contain credentials, a query or a fragment".into());
    }
    let host = url.host_str().ok_or("PentAGI server host is missing")?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1" || host == "::1";
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err("PentAGI requires HTTPS except for local loopback development".into());
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err("Set PentAGI URL to the service origin without a path".into());
    }
    let graphql = url.join("/api/v1/graphql").map_err(|error| error.to_string())?;
    Ok((graphql, token))
}

async fn graphql<T: DeserializeOwned>(query: &str, variables: Value) -> Result<T, String> {
    let (url, token) = config()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&json!({ "query": query, "variables": variables }))
        .send()
        .await
        .map_err(|error| format!("Cannot reach PentAGI: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("PentAGI API returned HTTP {}", response.status()));
    }
    let response: GraphResponse<T> = response.json().await
        .map_err(|_| "PentAGI returned an invalid GraphQL response".to_string())?;
    if let Some(errors) = response.errors {
        if !errors.is_empty() {
            return Err(errors.into_iter().take(2).map(|error| error.message)
                .collect::<Vec<_>>().join("; "));
        }
    }
    response.data.ok_or_else(|| "PentAGI returned no response data".to_string())
}

#[tauri::command]
pub async fn pentagi_status() -> PentagiConnection {
    #[derive(Deserialize)]
    struct Data { providers: Vec<PentagiProvider> }
    if let Err(reason) = config() {
        return PentagiConnection {
            configured: false, connected: false, detail: reason, providers: Vec::new(),
        };
    }
    match graphql::<Data>("query { providers { name type } }", json!({})).await {
        Ok(data) => PentagiConnection {
            configured: true, connected: true,
            detail: "Connected to PentAGI Go backend".into(),
            providers: data.providers,
        },
        Err(error) => PentagiConnection {
            configured: true, connected: false, detail: error, providers: Vec::new(),
        },
    }
}

#[tauri::command]
pub async fn pentagi_list_flows() -> Result<Vec<PentagiFlow>, String> {
    #[derive(Deserialize)]
    struct Data { flows: Vec<PentagiFlow> }
    graphql::<Data>(
        "query { flows { id title status provider { name type } createdAt updatedAt } }",
        json!({}),
    ).await.map(|data| data.flows)
}

#[derive(Debug, Deserialize)]
pub struct CreateFlowRequest {
    pub target: String,
    pub objective: String,
    pub provider: String,
    pub authorized: bool,
}

fn validate_request(request: &CreateFlowRequest) -> Result<String, String> {
    if !request.authorized {
        return Err("Explicit authorization for this target is required".into());
    }
    let url = Url::parse(request.target.trim())
        .map_err(|_| "Enter an HTTP(S) target URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
        || url.username() != "" || url.password().is_some() || url.fragment().is_some()
    {
        return Err("Target must be an HTTP(S) URL without credentials or fragments".into());
    }
    let objective = request.objective.trim();
    if objective.is_empty() || objective.len() > MAX_OBJECTIVE_BYTES {
        return Err("Describe an objective of at most 2000 bytes".into());
    }
    if request.provider.trim().is_empty() || request.provider.len() > 100 {
        return Err("Select a configured PentAGI provider".into());
    }
    Ok(url.to_string())
}

#[tauri::command]
pub async fn pentagi_create_flow(request: CreateFlowRequest) -> Result<PentagiFlow, String> {
    let target = validate_request(&request)?;
    // Preserve the declared scope in the upstream flow assignment. PentAGI still requires
    // its own enforcement of network/scope restrictions: an instruction is NOT a sandbox.
    let input = format!(
        "Authorized security assessment.\nTarget (only permitted host and path): {target}\n\
         Objective: {}\n\
         Do not access other hosts, escalate out of scope, perform destructive actions, \
         modify data, or use third-party infrastructure. Stop and request confirmation \
         whenever the task would exceed scope. Record evidence and report limitations.",
        request.objective.trim()
    );
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Data { create_flow: PentagiFlow }
    graphql::<Data>(
        "mutation($provider: String!, $input: String!) { createFlow(modelProvider: $provider, input: $input) { id title status provider { name type } createdAt updatedAt } }",
        json!({ "provider": request.provider, "input": input }),
    ).await.map(|data| data.create_flow)
}

#[tauri::command]
pub async fn pentagi_stop_flow(flow_id: String) -> Result<bool, String> {
    if flow_id.is_empty() || flow_id.len() > 64 || !flow_id.bytes().all(|v| v.is_ascii_digit()) {
        return Err("Invalid flow identifier".into());
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Data { stop_flow: String }
    graphql::<Data>(
        "mutation($id: ID!) { stopFlow(flowId: $id) }",
        json!({ "id": flow_id }),
    ).await.map(|data| data.stop_flow == "success")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PentagiTask {
    pub id: String,
    pub title: String,
    pub status: String,
    pub result: String,
    pub subtasks: Vec<PentagiSubtask>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PentagiSubtask {
    pub id: String,
    pub title: String,
    pub status: String,
    pub result: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PentagiAgentLog {
    pub id: String,
    pub executor: String,
    pub task: String,
    pub result: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PentagiToolLog {
    pub id: String,
    pub name: String,
    pub status: String,
    pub result: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}
#[derive(Debug, Serialize)]
pub struct PentagiFlowDetail {
    pub tasks: Vec<PentagiTask>,
    pub agents: Vec<PentagiAgentLog>,
    pub tools: Vec<PentagiToolLog>,
}
#[tauri::command]
pub async fn pentagi_flow_detail(flow_id: String) -> Result<PentagiFlowDetail, String> {
    if flow_id.is_empty() || flow_id.len() > 64 || !flow_id.bytes().all(|v| v.is_ascii_digit()) {
        return Err("Invalid flow identifier".into());
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Data {
        tasks: Vec<PentagiTask>,
        agent_logs: Vec<PentagiAgentLog>,
        tool_call_logs: Vec<PentagiToolLog>,
    }
    let data = graphql::<Data>(
        "query($id: ID!) { tasks(flowId: $id) { id title status result subtasks { id title status result } } agentLogs(flowId: $id) { id executor task result createdAt } toolCallLogs(flowId: $id) { id name status result createdAt } }",
        json!({ "id": flow_id }),
    ).await?;
    Ok(PentagiFlowDetail {
        tasks: data.tasks.into_iter().take(MAX_LOG_ITEMS).collect(),
        agents: data.agent_logs.into_iter().rev().take(MAX_LOG_ITEMS).collect(),
        tools: data.tool_call_logs.into_iter().rev().take(MAX_LOG_ITEMS).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(target: &str, authorized: bool) -> CreateFlowRequest {
        CreateFlowRequest {
            target: target.into(), objective: "Review configuration".into(),
            provider: "local".into(), authorized,
        }
    }
    #[test]
    fn requires_authorization_and_valid_target() {
        assert!(validate_request(&request("http://localhost:3000", false)).is_err());
        assert!(validate_request(&request("file:///etc/passwd", true)).is_err());
        assert!(validate_request(&request("https://user:pass@example.org", true)).is_err());
        assert!(validate_request(&request("https://example.org/app", true)).is_ok());
    }
    #[test]
    fn rejects_empty_or_oversized_objective() {
        let mut input = request("https://example.org", true);
        input.objective = " ".into();
        assert!(validate_request(&input).is_err());
        input.objective = "a".repeat(MAX_OBJECTIVE_BYTES + 1);
        assert!(validate_request(&input).is_err());
    }
}
