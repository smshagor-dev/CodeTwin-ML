//! Opt-in neural embeddings backed by a user-configured OpenAI-compatible model.
//! Source files, scan outputs, secrets and identifiers are never submitted as input.
use crate::{native_agents::NativeAgents, Database};
use reqwest::{blocking::Client, redirect::Policy, Url};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{env, io::Read, time::Duration};

const MIN_DIM: usize = 16;
const MAX_DIM: usize = 3072;
const MAX_RESPONSE_BYTES: u64 = 512_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct NeuralReadiness {
    pub configured: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralMatch {
    pub run_id: String,
    pub position: usize,
    pub role: String,
    pub status: String,
    pub score: f32,
}

struct EmbedConfig {
    endpoint: Url,
    model: String,
    token: Option<String>,
}
impl EmbedConfig {
    fn load() -> Result<Self, String> {
        let raw = env::var("CODETWIN_EMBEDDING_ENDPOINT")
            .map_err(|_| "Set CODETWIN_EMBEDDING_ENDPOINT to an OpenAI-compatible embeddings API".to_string())?;
        let endpoint=Url::parse(&raw).map_err(|_| "Invalid embedding endpoint".to_string())?;
        let host=endpoint.host_str().ok_or("Missing embedding endpoint hostname")?;
        let local=["localhost","127.0.0.1","::1"].contains(&host);
        if (endpoint.scheme()!="https" && !(local && endpoint.scheme()=="http"))
            || !endpoint.path().ends_with("/embeddings")
            || !endpoint.username().is_empty() || endpoint.password().is_some()
            || endpoint.query().is_some() || endpoint.fragment().is_some()
        {
            return Err("Embedding endpoint must be HTTPS (or local loopback HTTP) ending in /embeddings".into());
        }
        let model=env::var("CODETWIN_EMBEDDING_MODEL")
            .map_err(|_| "Set CODETWIN_EMBEDDING_MODEL".to_string())?;
        if model.is_empty() || model.len()>150 {return Err("Embedding model identifier invalid".into());}
        let token=env::var("CODETWIN_EMBEDDING_TOKEN").ok().filter(|v|!v.is_empty());
        if !local && token.is_none(){return Err("Remote embedding API requires a token".into());}
        Ok(Self {endpoint,model,token})
    }

    fn embed(&self, inputs: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if inputs.is_empty() || inputs.len()>8 || inputs.iter().any(|text|text.len()>160) {
            return Err("Embedding input must be 1–8 bounded, non-sensitive strings".into());
        }
        let body=serde_json::to_vec(&json!({"model":self.model,"input":inputs}))
            .map_err(err)?;
        let client=Client::builder().timeout(Duration::from_secs(35))
            .redirect(Policy::none()).build().map_err(err)?;
        let mut request=client.post(self.endpoint.clone())
            .header("Content-Type","application/json").body(body);
        if let Some(token)=&self.token{request=request.bearer_auth(token);}
        let response=request.send().map_err(|e|format!("Embedding provider unreachable: {e}"))?;
        if !response.status().is_success(){
            return Err(format!("Embedding provider returned HTTP {}",response.status()));
        }
        let mut bytes=Vec::new();
        response.take(MAX_RESPONSE_BYTES+1).read_to_end(&mut bytes).map_err(err)?;
        if bytes.len() as u64>MAX_RESPONSE_BYTES {return Err("Embedding response too large".into());}
        let value:Value=serde_json::from_slice(&bytes).map_err(|_|"Invalid embedding JSON")?;
        parse_embedding_response(&value,inputs.len())
    }
}

fn normalized(values: &[Value]) -> Result<Vec<f32>, String> {
    if !(MIN_DIM..=MAX_DIM).contains(&values.len()) {
        return Err("Unsupported neural embedding dimension".into());
    }
    let mut floats=Vec::with_capacity(values.len());
    for value in values {
        let float=value.as_f64().ok_or("Embedding must contain numeric values")?;
        if !float.is_finite() || float.abs()>1e6 {
            return Err("Neural embedding contains non-finite or unsafe values".into());
        }
        floats.push(float as f32);
    }
    let length=(floats.iter().map(|v|(*v as f64)*(*v as f64)).sum::<f64>()).sqrt();
    if length<=f64::EPSILON {return Err("Neural embedding has zero magnitude".into());}
    for value in &mut floats {*value=(*value as f64/length) as f32;}
    Ok(floats)
}

fn parse_embedding_response(value:&Value, expected:usize)->Result<Vec<Vec<f32>>,String>{
    let items=value.get("data").and_then(Value::as_array)
        .ok_or("Embedding response has no data array")?;
    if items.len()!=expected {return Err("Embedding response count mismatch".into());}
    let mut result=vec![None;expected];
    let mut dimension=None;
    for item in items {
        let index=item.get("index").and_then(Value::as_u64)
            .ok_or("Missing embedding index")? as usize;
        if index>=expected || result[index].is_some() {return Err("Duplicate or invalid embedding index".into());}
        let raw=item.get("embedding").and_then(Value::as_array)
            .ok_or("Embedding data is missing")?;
        let vector=normalized(raw)?;
        if dimension.is_some_and(|n|n!=vector.len()){
            return Err("Model returned mixed embedding dimensions".into());
        }
        dimension=Some(vector.len());
        result[index]=Some(vector);
    }
    result.into_iter().map(|v|v.ok_or("Missing vector from embedding response".into())).collect()
}

pub struct NeuralMemory<'a> { db:&'a Database }
impl<'a> NeuralMemory<'a>{
    pub const fn new(db:&'a Database)->Self{Self {db}}
    pub fn readiness()->NeuralReadiness {
        match EmbedConfig::load(){
            Ok(_)=>NeuralReadiness{configured:true,detail:"An opt-in neural embeddings provider is configured".into()},
            Err(e)=>NeuralReadiness{configured:false,detail:e},
        }
    }
    /// Only short role/tool/status descriptions from a terminal review are sent to the model.
    pub fn index_run(&self,run_id:&str,consent:bool)->Result<usize,String>{
        if !consent {return Err("Explicit embedding consent required".into());}
        let run=NativeAgents::new(self.db).get(run_id)?;
        if !["completed","failed","cancelled","interrupted"].contains(&run.status.as_str()){
            return Err("Only finished review provenance may be embedded".into());
        }
        let config=EmbedConfig::load()?;
        let steps=run.steps.iter().filter(|s|s.status=="completed" || s.status=="failed")
            .collect::<Vec<_>>();
        if steps.is_empty(){return Ok(0);}
        let input=steps.iter().map(|step|format!("{} {} {}",step.role,step.tool,step.status))
            .collect::<Vec<_>>();
        let vectors=config.embed(&input)?;
        let tx=self.db.connection().unchecked_transaction().map_err(err)?;
        for (step,vector) in steps.iter().zip(vectors.iter()){
            tx.execute(
                "INSERT INTO native_neural_embeddings(project_id,run_id,position,model_id,dimensions,vector_json)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(run_id,position,model_id) DO UPDATE SET
                 dimensions=excluded.dimensions,vector_json=excluded.vector_json",
                params![run.project_id,run.id,step.position,config.model,vector.len(),
                    serde_json::to_string(vector).map_err(err)?],
            ).map_err(err)?;
        }
        tx.commit().map_err(err)?;
        Ok(steps.len())
    }
    pub fn search(&self,project_id:&str,query:&str,limit:usize,consent:bool)->Result<Vec<NeuralMatch>,String>{
        if !consent {return Err("Explicit query embedding consent required".into());}
        if project_id.is_empty() || project_id.len()>256 || query.trim().is_empty()
            || query.len()>150 {return Err("Invalid bounded search query".into());}
        let config=EmbedConfig::load()?;
        let q=config.embed(&[query.to_owned()])?.remove(0);
        let mut stmt=self.db.connection().prepare(
            "SELECT v.run_id,v.position,s.role,s.status,v.vector_json
             FROM native_neural_embeddings v JOIN native_agent_steps s
             ON s.run_id=v.run_id AND s.position=v.position
             WHERE v.project_id=?1 AND v.model_id=?2 LIMIT 500",
        ).map_err(err)?;
        let items=stmt.query_map(params![project_id,config.model],|row|{
            Ok((row.get::<_,String>(0)?,row.get::<_,usize>(1)?,
                row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?))
        }).map_err(err)?.collect::<Result<Vec<_>,_>>().map_err(err)?;
        let mut matches=Vec::new();
        for (run_id,position,role,status,payload) in items {
            let Ok(vector)=serde_json::from_str::<Vec<f32>>(&payload) else {continue};
            if vector.len()!=q.len() || vector.iter().any(|v|!v.is_finite()){continue;}
            let score=q.iter().zip(vector).map(|(a,b)|a*b).sum::<f32>();
            if score>0.0 {matches.push(NeuralMatch {run_id,position,role,status,score});}
        }
        matches.sort_by(|a,b|b.score.total_cmp(&a.score));
        matches.truncate(limit.clamp(1,25));
        Ok(matches)
    }
}
fn err(e:impl std::fmt::Display)->String{e.to_string()}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_malformed_nonfinite_wrong_size_and_duplicate_neural_vectors(){
        assert!(parse_embedding_response(&json!({"data":[{"index":0,"embedding":[1,2]}]}),1).is_err());
        let v=vec![1.0;32];
        let result=parse_embedding_response(&json!({"data":[{"index":0,"embedding":v}]}),1).unwrap();
        assert!((result[0].iter().map(|n|n*n).sum::<f32>()-1.0).abs()<0.0001);
        assert!(parse_embedding_response(&json!({"data":[{"index":0,"embedding":vec![1.0;32]},{"index":0,"embedding":vec![1.0;32]}]}),2).is_err());
        assert!(normalized(&vec![json!(0.0);32]).is_err());
    }
}
