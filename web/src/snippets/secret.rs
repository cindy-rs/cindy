fn issue_token() -> cindy::Secret<String> {
    let token = cindy::secret!("prod", "hunter2".to_string());
    token
}
