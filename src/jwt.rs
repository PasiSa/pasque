use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

use crate::PsqError;

/// Claims and functions to operate a JSON Web Tokens in Pasque.
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt {
    sub: String,
    exp: usize,
    iat: usize,
    permissions: Vec<String>,
}

impl Jwt {
    /// Create a JSON web token.
    ///
    /// `sub` is the JWT subject, typically a user ID. `duration` defines when
    /// the token expires. Expiry time is "now" + `duration`. `permissions` tell
    /// what the token is good for: each Pasque endpoint may define a permission
    /// string that is required in the client token to allow a stream to the
    /// endpoint. `secret` is the shared secret used to encode and decode the
    /// token.
    ///
    /// Returns the token that can be included in the HTTP Authorization header.
    pub fn create_token(
        sub: String,
        lifetime: Duration,
        permissions: Vec<String>,
        secret: &[u8],
    ) -> Result<String, PsqError> {
        let now = Utc::now();
        let claims = Jwt {
            sub,
            exp: (now + lifetime).timestamp() as usize,
            iat: now.timestamp() as usize,
            permissions,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )?;
        Ok(token)
    }

    /// Verify a JSON web token.
    ///
    /// `secret` is the shared secret used to verify the token. Also expiry time
    /// is verified. Returns the claims in the token, if verification succeeds.
    pub fn verify_token(token: &str, secret: &[u8]) -> Result<TokenData<Jwt>, PsqError> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Jwt>(token, &DecodingKey::from_secret(secret), &validation)?;
        Ok(token_data)
    }

    /// `true` if claims contain the given permission string.
    pub fn has_permission(&self, permission: &String) -> bool {
        self.permissions.contains(permission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    const SECRET: &[u8] = b"test-secret";

    #[test]
    fn valid_token() {
        let token = Jwt::create_token(
            "user1".to_string(),
            Duration::seconds(120),
            vec!["read".to_string()],
            SECRET,
        )
        .expect("failed to create token");

        let result = Jwt::verify_token(&token, SECRET);
        let claims = result.unwrap().claims;
        assert_eq!(claims.sub, "user1");
        assert!(claims.has_permission(&"read".to_string()));
    }

    #[test]
    fn expired_token() {
        let token = Jwt::create_token(
            "user2".to_string(),
            Duration::seconds(-120),
            vec!["write".to_string()],
            SECRET,
        )
        .expect("failed to create token");

        let result = Jwt::verify_token(&token, SECRET);
        assert!(result.is_err(), "Expected token to be expired");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("ExpiredSignature"),
            "Expected ExpiredSignature error, got: {}",
            err
        );
    }

    #[test]
    fn invalid_permission() {
        let token = Jwt::create_token(
            "user1".to_string(),
            Duration::seconds(120),
            vec!["invalid".to_string(), "other".to_string()],
            SECRET,
        )
        .expect("failed to create token");

        let result = Jwt::verify_token(&token, SECRET);
        let claims = result.unwrap().claims;
        assert_eq!(claims.sub, "user1");
        assert!(!claims.has_permission(&"read".to_string()));
    }
}
