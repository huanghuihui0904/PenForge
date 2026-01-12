import os
import json
import requests
from pathlib import Path
from dotenv import load_dotenv


class RAGQueryTool:

    def __init__(
        self,
        env_file=None,
        model="sonar",  
        base_url="https://api.perplexity.ai/chat/completions",
        timeout=60,
    ):
        # Find repository root and load .env file if not specified
        if env_file is None:
            repo_root = Path(__file__).parent.parent
            env_file = repo_root / ".env"
        load_dotenv(env_file)

        self.api_key = os.getenv("PERPLEXITY_API_KEY")
        if not self.api_key:
            raise RuntimeError("[ERROR] PERPLEXITY_API_KEY not set in .env")

        self.model = model
        self.base_url = base_url
        
        self.system_prompt = (
            "You are a penetration testing assistant working in a controlled lab. "
            "Always structure your reply in plain text with these sections:\n\n"
            "Attack Type: <name of the attack>\n"
            "Success Criteria: <the exact condition to evaluate success>\n"
            "Strategy: <the high-level approach to perform it>\n"
            "Tools and Usage:\n"
            "  - Tool: <name of tool>\n"
            "    How to Use: <step-by-step usage of this tool in this context>\n"
            "Other Suggestions: <variations, notes, or recommendations>\n\n"
            "Keep this structure consistent for every answer."
        )

        self.timeout = timeout

    def run(self, query_text: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": query_text},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            r = requests.post(self.base_url, headers=headers, json=payload, timeout=self.timeout)
            if not r.ok:
                try:
                    err = r.json()
                    print("[Perplexity HTTP]", r.status_code, json.dumps(err, indent=2))
                except Exception:
                    print("[Perplexity HTTP]", r.status_code, r.text[:1000])
                r.raise_for_status()

            data = r.json()
            answer = data["choices"][0]["message"]["content"]

            sources = [
                {"title": s.get("title"), "url": s.get("url"), "date": s.get("date")}
                for s in (data.get("search_results") or [])
            ]
            if sources:
                print("[INFO] Sources:")
                for s in sources:
                    print(f"- {s['title'] or s['url']} — {s['url']}")

            print(f"[INFO] RAG search successful: {answer}")
            return answer

        except Exception as e:
            print(f"[ERROR] RAG search failed: {e}")
            return "[ERROR] [RAG search failed]"

