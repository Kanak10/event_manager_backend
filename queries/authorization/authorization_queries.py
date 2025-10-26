class AuthorizationQueries:
    create_issued_token_tabel = """
        CREATE TABLE IF NOT EXISTS issued_tokens (
            token VARCHAR(255),
            email_id VARCHAR(255),
            session_id VARCHAR(255)
        );
    """
    insert_in_issued_token_tabel = """
        INSERT INTO issued_tokens (token, email_id, session_id) VALUES (%s,%s,%s)
    """