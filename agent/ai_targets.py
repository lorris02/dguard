AI_DOMAINS: set[str] = {
    # Anthropic
    "api.anthropic.com",
    "claude.ai",
    # OpenAI / ChatGPT
    "api.openai.com",
    "chat.openai.com",
    "chatgpt.com",
    # Google
    "generativelanguage.googleapis.com",
    "gemini.google.com",
    "aistudio.google.com",
    # Microsoft Copilot
    "copilot.microsoft.com",
    "sydney.bing.com",
    # Mistral
    "api.mistral.ai",
    "chat.mistral.ai",
    # Cohere
    "api.cohere.ai",
    # Meta / Together / Groq (popular API providers)
    "api.together.xyz",
    "api.groq.com",
    # Perplexity
    "api.perplexity.ai",
    "www.perplexity.ai",
    # HuggingFace
    "huggingface.co",
    "api-inference.huggingface.co",
}


def is_ai_target(host: str) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in AI_DOMAINS)
