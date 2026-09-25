use crate::{AppError, AppResult};
use reqwest::{Client, Method};
use serde_json::Value;
#[derive(Clone)]
pub struct Database {
    pub client: Client,
    pub base: String,
    pub token: String,
}
impl Database {
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        tenant: Option<&str>,
        body: Option<&Value>,
    ) -> AppResult<Value> {
        let mut request = self
            .client
            .request(method, format!("{}{}", self.base, path))
            .bearer_auth(&self.token);
        if let Some(tenant) = tenant {
            request = request.header("x-tenant-id", tenant);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| AppError::unavailable("Database service unavailable"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(AppError::new(status, "Database operation failed"));
        }
        response
            .json()
            .await
            .map_err(|_| AppError::unavailable("Invalid database response"))
    }
    pub async fn identity(&self, email: &str) -> AppResult<Value> {
        let mut url = reqwest::Url::parse(&format!("{}/v1/identities/", self.base))
            .map_err(|_| AppError::unavailable("Invalid service configuration"))?;
        url.path_segments_mut()
            .map_err(|_| AppError::unavailable("Invalid service configuration"))?
            .pop_if_empty()
            .push(email);
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| AppError::unavailable("Database unavailable"))?;
        if !response.status().is_success() {
            return Err(AppError::new(response.status(), "Identity not found"));
        }
        response
            .json()
            .await
            .map_err(|_| AppError::unavailable("Invalid identity response"))
    }
    pub async fn records(&self, tenant: &str, collection: &str) -> AppResult<Vec<Value>> {
        let result = self
            .call(
                Method::GET,
                &format!("/v1/records/{collection}"),
                Some(tenant),
                None,
            )
            .await?;
        result["records"]
            .as_array()
            .cloned()
            .ok_or_else(|| AppError::unavailable("Invalid records response"))
    }
    pub async fn save(
        &self,
        tenant: &str,
        collection: &str,
        id: &str,
        value: &Value,
    ) -> AppResult<Value> {
        self.call(
            Method::PUT,
            &format!("/v1/records/{collection}/{id}"),
            Some(tenant),
            Some(value),
        )
        .await
    }
    pub async fn create(
        &self,
        tenant: &str,
        collection: &str,
        id: &str,
        value: &Value,
    ) -> AppResult<Value> {
        self.call(
            Method::POST,
            &format!("/v1/records/{collection}/{id}"),
            Some(tenant),
            Some(value),
        )
        .await
    }
}
