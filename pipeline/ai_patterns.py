"""Regex rules used to tag CVEs.

1. AI_FINDERS: a CVE is "AI-attributed" when its CNA credits name an AI
   vulnerability-discovery system or an organisation whose public disclosures are
   made with AI agents, or when its description explicitly says the flaw was found
   with AI. The organisation list follows the Berkeley Vulnerability Initiative's
   Agentic Vulnerability Coverage Map (vuln.cs.berkeley.edu) plus a few systems it
   does not track (Google Big Sleep, Intel AI-assisted static analysis, Alpha-Omega
   Scrutineer). This is a lower bound: most vendors do not credit tools.

2. AI_SOFTWARE: a CVE is "in AI software" when the affected product/vendor or the
   description points at an LLM, agent framework, model-serving or ML platform.
"""

from __future__ import annotations

import re

# (label, compiled regex). Order matters: first match wins for the org label.
AI_FINDERS: list[tuple[str, re.Pattern]] = [
    ("Anthropic (Claude)", re.compile(r"anthropic|\bclaude\b|\bmythos\b|glasswing", re.I)),
    ("OpenAI (Codex / GPT)", re.compile(r"openai|\bcodex\b|aardvark|\bgpt-\d", re.I)),
    ("Google (Big Sleep / Gemini)", re.compile(r"big sleep|codemender|sec-gemini|naptime|\bgemini (cli|agent|2|3)", re.I)),
    ("AISLE", re.compile(r"\bAISLE\b|aisle research|found by aisle")),
    ("XBOW", re.compile(r"\bxbow\b", re.I)),
    ("Nebula Security", re.compile(r"(?<!huawei )nebula security(?! lab)|nebusec", re.I)),
    ("BugBunny.ai", re.compile(r"bugbunny", re.I)),
    ("Tencent (Xuanwu Atuin / Zhuque)", re.compile(r"\batuin\b|xlabai|zhuque|ai-infra-guard", re.I)),
    ("Hacktron AI", re.compile(r"hacktron", re.I)),
    ("ProjectDiscovery Neo", re.compile(r"neo by projectdiscovery|neo ai engineer|neo\.projectdiscovery", re.I)),
    ("Calif.io", re.compile(r"calif\.io", re.I)),
    ("depthfirst", re.compile(r"depthfirst", re.I)),
    ("ZeroPath", re.compile(r"zeropath", re.I)),
    ("Ant Group AI Security Lab", re.compile(r"antaisecuritylab", re.I)),
    ("CodeAnt AI", re.compile(r"codeant", re.I)),
    ("Theori Xint", re.compile(r"\bXINT\b|xint\.io")),
    ("Aether AI", re.compile(r"aether[- ]ai", re.I)),
    ("ZAST.AI", re.compile(r"zast\.ai", re.I)),
    ("Fluid Attacks AI SAST", re.compile(r"fluid attacks' ai|ai sast", re.I)),
    ("GitHub Taskflow Agent", re.compile(r"taskflow agent", re.I)),
    ("Microsoft autonomous code security", re.compile(r"autonomous code security", re.I)),
    ("Parameter.ai", re.compile(r"parameter autonomous|parameter\.ai", re.I)),
    ("Other AI agent or tool", re.compile(
        r"ai[- ]assisted|\bai agent\b|security ai agent|ai[- ]powered|\bllm\b|deepseek agent|"
        r"ai[- ]driven|ai vulnerability|automated vulnerability discovery engine|scrutineer",
        re.I,
    )),
]

# Applied to the description text: explicit statements that AI found the flaw.
AI_DESC = re.compile(
    r"(discovered|found|identified|detected|uncovered)\s+(using|with|by|via)\s+(an?\s+)?"
    r"(ai\b|ai-assisted|llm|large language model|claude|gpt|codex|gemini|automated ai)|"
    r"ai-assisted (static )?analysis|\(using claude\)|with the help of (ai|an ai|claude|an llm)|"
    r"powered by mythos|"
    # AI code review in the Linux kernel: Google's Sashiko (Gemini) and other LLM reviewers named in fix descriptions
    r"\bsashiko\b|\blollm\b|found by (an )?ai\b|\bai review|an llm scan|\bai-generated (bug )?report",
    re.I,
)


PERSON_CLAUDE = re.compile(r"(Jean-)?Claude (?!Code|Security|Opus|Fable|Sonnet|Haiku|Agents?\b|AI\b)[A-Z][a-z]+")


def ai_finder(credits: str | None, description: str | None) -> str | None:
    """Return the AI finder label, or None."""
    text = credits if isinstance(credits, str) else ""
    description = description if isinstance(description, str) else ""
    # People whose first name is Claude (e.g. "Claude Ndanda") are not the model.
    text = PERSON_CLAUDE.sub("", text)
    if text:
        for label, pat in AI_FINDERS:
            if pat.search(text):
                return label
    if description and AI_DESC.search(description):
        for label, pat in AI_FINDERS[:3]:
            if pat.search(description):
                return label
        if re.search(r"intel product security", description, re.I):
            return "Intel AI-assisted analysis"
        if re.search(r"\bsashiko\b", description, re.I):
            return "Google Sashiko (kernel review)"
        return "Other AI agent or tool"
    return None


AI_SOFTWARE = re.compile(
    r"\b(?:llm|large language model|prompt injection|langchain|langgraph|llama[._ ]?index|llama\.cpp|ollama|vllm|"
    r"langflow|litellm|comfyui|gradio|hugging ?face|transformers library|pytorch|tensorflow|keras|onnx|"
    r"mlflow|ray (?:dashboard|cluster)|triton inference|bentoml|kserve|torchserve|stable diffusion|dify|flowise|"
    r"open ?webui|anythingllm|lobe ?chat|chatgpt|openai|anthropic|claude|copilot|cursor ide|anysphere|windsurf|"
    r"gemini cli|codex cli|model context protocol|mcp server|\bmcp\b|ai agent|agentic|autogpt|auto-gpt|crewai|"
    r"autogen|semantic kernel|haystack|milvus|qdrant|chromadb|weaviate|pinecone|vector database|"
    r"localai|text-generation-webui|sglang|xinference|n8n|ragflow|fastgpt|maxkb|new-api|one-api|"
    r"lollms|h2o ?gpt|privategpt|jan\.ai|lm studio|kubeflow|nvidia nemo|nemo framework|triton server)\b",
    re.I,
)
