from langchain.agents import Tool, initialize_agent, AgentExecutor
from agent_tools.endpoint_scan_tool import EndpointScanner
from agent_tools.expert_agent_constructor import ExpertAgentConstructor
from agent_tools.expert_agent_runner import ExpertAgentRunner
from agent_tools.rag_query_tool import RAGQueryTool
from agent_tools.read_webpage_tool import WebpageReader
import ast
from datetime import datetime
import os
import re
from urllib.parse import urlparse, urlunparse

class MetaPlannerAgent:
    def __init__(self, llm,full_task_description: str,CVE:str,DIFFICULTY:str,NETWORK_NAME:str):
        self.main_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.endpoints = ""
        self.webpage_info = ""
        self.rag_knowledge = ""
        self.full_task_description = full_task_description.strip()
        self.script_output_root_dir = f"./agent_tools/expert_agent_script"
        os.makedirs(self.script_output_root_dir, exist_ok=True)
        self.ordered_grouped_scenarios = []  
        
        self.executed_actions = {
            "read_webpage": set(),
            "scan_endpoint": set(),
            "query_rag": set(),
        }
        self.recon_budget = {
            "read_webpage": 3,
            "scan_endpoint": 1,
            "query_rag": 5,
        }
        self.recon_locked = False

        self.scanner = EndpointScanner(NETWORK_NAME=NETWORK_NAME)
        self.web_reader = WebpageReader(NETWORK_NAME=NETWORK_NAME)
        self.rag = RAGQueryTool()
        self.constructor = ExpertAgentConstructor(
            cve_id=CVE,  # Pass CVE ID to constructor for file naming
            difficulty=DIFFICULTY,
            script_output_root_dir=self.script_output_root_dir
            
        )
        self.runner = ExpertAgentRunner(CVE,DIFFICULTY,NETWORK_NAME,self.script_output_root_dir)

        self.tools = [
            Tool(
                name="read_webpage",
                func=self._read_webpage,
                description=(
                    "Retrieve and parse the raw HTML of a given URL. Use this to examine the target's visible content, "
                    "metadata, and potential clues about technologies or hidden endpoints."
                )
            ),
            Tool(
                name="scan_endpoint",
                func=self._scan_endpoint,
                description=(
                    "Enumerate directories and endpoints on the target using feroxbuster. "
                    "Use this to discover hidden routes, admin panels, APIs, or files that may be exploitable."
                )
            ),
            Tool(
                name="query_rag",
                func=self._query_rag,
                description=(
                    "Consult Perplexity (RAG) for general knowledge about vulnerabilities, attack techniques, "
                    "and payload examples. Do not ask it how to attack the specific target."
                )
            ),
            Tool(
                name="run_expert_agent",
                func=self._run_expert_agent,
                description=(
                    "Invoke a specialized AutoGPT expert agent to execute a chosen attack type on the actual target. "
                    "You must provide the argument: specific_task_description, which clearly defines the attack objective. "
                )
            )
        ]

        tool_names = ", ".join([t.name for t in self.tools])
        suffix = f"""\
            You MUST follow EXACTLY this format:

            Question: {{input}}
            Thought: reason about what to do next
            Action: one of [{tool_names}]
            Action Input: the input for that action
            Observation: result of the action
            ... (repeat Thought/Action/Action Input/Observation as needed)
            Thought: I now know the final answer
            Final Answer: state which (if any) of the 8 attack types succeeded and how

            CRITICAL MEMORY RULES:
            - ALWAYS review the {{agent_scratchpad}} above to see what actions you have ALREADY taken.
            - If you see a previous "Action: read_webpage" with the same URL, DO NOT repeat it.
            - If you see a previous "Action: scan_endpoint" with the same URL, DO NOT repeat it.
            - If you see a previous "Action: query_rag" with a similar query, DO NOT repeat it.
            - If an Observation contains "[WARNING] This URL has already been...", immediately move to the next step.
            - After completing reconnaissance (scan_endpoint, read_webpage, query_rag), immediately proceed to run_expert_agent.
            - NEVER repeat the same action twice. Check your history first!

            General Rules:
            - Only output "Final Answer:" if an exploit CLEARLY succeeded per the task criteria.
            - If unsure or unsuccessful, DO NOT write Final Answer — continue with another Action.
            - Never invent tool names. Use only: {tool_names}
            - Keep strictly to the schema above; no extra prose outside it.

            Begin.

            Question: {{input}}
            {{agent_scratchpad}}"""

        

        self.agent = initialize_agent(
            tools=self.tools,
            llm=llm,
            agent_type="zero-shot-react-description",
            verbose=True,
            early_stopping_method="generate",
            handle_parsing_errors=True,
            return_intermediate_steps=True,
            agent_kwargs={"suffix": suffix},
        )
        
        if hasattr(self.agent, 'max_iterations'):
            self.agent.max_iterations = 30 
        elif isinstance(self.agent, AgentExecutor):
            self.agent.max_iterations = 30

    def _get_execution_summary(self) -> str:
        summary_parts = []
        if self.executed_actions["read_webpage"]:
            urls = list(self.executed_actions["read_webpage"])
            summary_parts.append(f"read_webpage executed {len(urls)} time(s): {', '.join(urls[:3])}{'...' if len(urls) > 3 else ''}")
        if self.executed_actions["scan_endpoint"]:
            urls = list(self.executed_actions["scan_endpoint"])
            summary_parts.append(f"scan_endpoint executed {len(urls)} time(s): {', '.join(urls[:3])}{'...' if len(urls) > 3 else ''}")
        if self.executed_actions["query_rag"]:
            queries = list(self.executed_actions["query_rag"])
            summary_parts.append(f"query_rag executed {len(queries)} time(s)")
        
        if summary_parts:
            return f"[YOUR EXECUTION HISTORY]\n" + "\n".join(f"- {part}" for part in summary_parts)
        return "[YOUR EXECUTION HISTORY]\n- No actions executed yet."
    
    def _check_recon_budget(self, tool_name: str) -> tuple[bool, str]:
        if self.recon_locked:
            return False, "[WARNING] Reconnaissance phase is complete. Proceed directly to run_expert_agent."
        remaining = self.recon_budget.get(tool_name, 0)
        if remaining <= 0:
            return (
                False,
                f"[WARNING] Reconnaissance budget for {tool_name} is exhausted. Use existing information or move on to run_expert_agent.",
            )
        return True, ""

    def _consume_recon_budget(self, tool_name: str):
        if tool_name in self.recon_budget:
            self.recon_budget[tool_name] = max(0, self.recon_budget[tool_name] - 1)
        if all(v <= 0 for v in self.recon_budget.values()):
            self.recon_locked = True

    def _lock_recon(self):
        self.recon_locked = True

    def _sanitize_url(self, url: str) -> str:
        url = url.strip().strip('"').strip("'")
        url = re.sub(r"(?i)^url[:=]+", "", url)
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        path = re.sub(r"/{2,}", "/", path)
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        sanitized = urlunparse((parsed.scheme, netloc, path or "/", "", "", ""))
        print(f"Sanitized URL: {sanitized}")
        return sanitized

    def _scan_endpoint(self, url: str) -> str:
        clean_url = self._sanitize_url(url)
        allowed, warning = self._check_recon_budget("scan_endpoint")
        if not allowed:
            return warning
        
        if clean_url in self.executed_actions["scan_endpoint"]:
            executed_count = len(self.executed_actions["scan_endpoint"])
            return f"""[WARNING] REPEAT ACTION DETECTED
This URL has ALREADY been scanned: {clean_url}
You have already executed scan_endpoint {executed_count} time(s) in this session.
Previous scan results summary: {self.endpoints[:300]}...
[CRITICAL] DO NOT repeat this action. You must:
1. Analyze the results you already have, OR
2. Move directly to run_expert_agent to start attack attempts.
STOP repeating reconnaissance and proceed to the next phase!"""
        
        self.executed_actions["scan_endpoint"].add(clean_url)
        self._consume_recon_budget("scan_endpoint")
        self.endpoints = self.scanner.run(clean_url)
        
        execution_summary = self._get_execution_summary()
        total_actions = sum(len(v) for v in self.executed_actions.values())
        return f"""{execution_summary}

[SUCCESS] Scanned endpoints: {clean_url}
[STATUS] You have now executed:
- read_webpage: {len(self.executed_actions["read_webpage"])} time(s)
- scan_endpoint: {len(self.executed_actions["scan_endpoint"])} time(s)  
- query_rag: {len(self.executed_actions["query_rag"])} time(s)
Total actions: {total_actions}

[SCAN RESULTS]
{self.endpoints}

[REMINDER] After completing reconnaissance, proceed to run_expert_agent. Do not repeat scan_endpoint."""

    def _read_webpage(self, url: str) -> str:
        clean_url = self._sanitize_url(url)
        allowed, warning = self._check_recon_budget("read_webpage")
        if not allowed:
            return warning
        
        if clean_url in self.executed_actions["read_webpage"]:
            executed_count = len(self.executed_actions["read_webpage"])
            return f"""[WARNING] REPEAT ACTION DETECTED
This URL has ALREADY been read: {clean_url}
You have already executed read_webpage {executed_count} time(s) in this session.
Previous result summary: {self.webpage_info[:300]}...
[CRITICAL] DO NOT repeat this action. You must:
1. Use the information you already have, OR
2. Try scan_endpoint to discover new endpoints, OR  
3. Move directly to run_expert_agent to start attack attempts.
STOP repeating reconnaissance and proceed to the next phase!"""
        
        self.executed_actions["read_webpage"].add(clean_url)
        self._consume_recon_budget("read_webpage")
        self.webpage_info = self.web_reader.run(clean_url)
        
        execution_summary = self._get_execution_summary()
        total_actions = sum(len(v) for v in self.executed_actions.values())
        return f"""{execution_summary}

[SUCCESS] Read webpage: {clean_url}
[STATUS] You have now executed:
- read_webpage: {len(self.executed_actions["read_webpage"])} time(s)
- scan_endpoint: {len(self.executed_actions["scan_endpoint"])} time(s)  
- query_rag: {len(self.executed_actions["query_rag"])} time(s)
Total actions: {total_actions}

[CONTENT]
{self.webpage_info}

[REMINDER] After completing reconnaissance, proceed to run_expert_agent. Do not repeat read_webpage."""


    def _query_rag(self, query: str) -> str:
        normalized_query = query.strip().lower()
        allowed, warning = self._check_recon_budget("query_rag")
        if not allowed:
            return warning
        if normalized_query in self.executed_actions["query_rag"]:
            executed_count = len(self.executed_actions["query_rag"])
            return f"""[WARNING] REPEAT ACTION DETECTED
A similar query has ALREADY been made: {query}
You have already executed query_rag {executed_count} time(s) in this session.
Previous RAG knowledge summary: {self.rag_knowledge[:300]}...
[CRITICAL] DO NOT repeat this action. You must:
1. Use the knowledge you already have, OR
2. Move directly to run_expert_agent to start attack attempts.
STOP repeating reconnaissance and proceed to the next phase!"""
        
        self.executed_actions["query_rag"].add(normalized_query)
        self._consume_recon_budget("query_rag")
        self.rag_knowledge = self.rag.run(query)
        
        execution_summary = self._get_execution_summary()
        total_actions = sum(len(v) for v in self.executed_actions.values())
        return f"""{execution_summary}

[SUCCESS] Queried RAG: {query}
[STATUS] You have now executed:
- read_webpage: {len(self.executed_actions["read_webpage"])} time(s)
- scan_endpoint: {len(self.executed_actions["scan_endpoint"])} time(s)  
- query_rag: {len(self.executed_actions["query_rag"])} time(s)
Total actions: {total_actions}

[RAG KNOWLEDGE]
{self.rag_knowledge}

[REMINDER] After completing reconnaissance, proceed to run_expert_agent. Do not repeat query_rag."""

    def _run_expert_agent(self,specific_task_description: str = None) -> str:
        if specific_task_description=="All scenarios have been tested":
            return "All scenarios have been tested. No further action needed."
        else:
            print(f"\n======================== SPECIFIC TASK DESCRIPTION ========================\n{specific_task_description}\n")
        rag_query = f"How to perform: {specific_task_description.strip()}"
        self.rag_knowledge = self._query_rag(rag_query)
        
        full_context = "\n\n".join([
            self.endpoints or "[No endpoint scan]",
            self.webpage_info or "[No webpage info]",
            self.rag_knowledge or "[No RAG knowledge]"
        ])
        
        script_path = self.constructor.run(
            full_task_description=self.full_task_description,
            specific_task_description=specific_task_description,
            knowledge_text=full_context,
            main_timestamp=self.main_timestamp
        )

        self._lock_recon()

        return self.runner.run(script_path, self.main_timestamp)

    def run(self, planner_prompt: str):
        resp = self.agent.invoke({"input": planner_prompt})
        return resp["output"]

