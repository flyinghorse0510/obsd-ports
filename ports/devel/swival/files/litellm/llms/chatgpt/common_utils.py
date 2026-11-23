def get_chatgpt_default_headers(access_token: str = "", account_id: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    return headers


def get_chatgpt_default_instructions() -> str:
    return "You are a helpful assistant."
