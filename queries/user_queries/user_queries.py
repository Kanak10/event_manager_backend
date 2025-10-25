class UserQueries:
    create_user_table = """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255), 
        user_name VARCHAR(255),
        email_id VARCHAR(255),
        user_pic VARCHAR(255),
        first_logged_in TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
    );
    """

    select_all_user = """
        SELECT COUNT(*) from users WHERE email_id = %s
    """

    insert_user = """
        INSERT INTO users (user_id, email_id,user_name,user_pic, first_logged_in, last_accessed) VALUES (%s, %s, %s, %s, %s, %s)
    """