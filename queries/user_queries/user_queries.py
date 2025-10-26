class UserQueries:
    create_user_table = """
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            google_id VARCHAR(255) UNIQUE NULL,
            user_email VARCHAR(255) UNIQUE NOT NULL,
            user_name VARCHAR(255),
            user_pic TEXT,
            hashed_password TEXT,
            auth_provider VARCHAR(50) DEFAULT 'email',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
        );
    """

    count_user = """
        SELECT COUNT(*) from users WHERE user_email = %s
    """

    find_user_with_user_name = """
        SELECT COUNT(*) from users WHERE user_name = %s
    """

    insert_user = """
        INSERT INTO users (
            google_id,
            user_email,
            user_name,
            user_pic,
            hashed_password,
            auth_provider,
            created_at,
            updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """

    update_updated_at_column = """
        UPDATE users
        SET updated_at = %s
        WHERE user_email = %s;
    """

    fetch_user_for_signin = """
        SELECT google_id,
                user_email,
                user_name,
                user_pic,
                hashed_password,
                auth_provider,
                created_at,
                updated_at
        from users WHERE user_email = %s
    """

    fetch_user_details = """

    """
