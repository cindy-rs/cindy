fn use_token(token: cindy::Secret<String>) -> cindy::Result<String> {
    let token: String = token.reveal()?;
    Ok(token)
}
