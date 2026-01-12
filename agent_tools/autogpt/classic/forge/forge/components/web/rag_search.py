from typing import Iterator, Optional
import requests
import logging
import json
from pydantic import BaseModel

from forge.agent.components import ConfigurableComponent
from forge.agent.protocols import CommandProvider, DirectiveProvider
from forge.command import Command, command
from forge.models.json_schema import JSONSchema

logger = logging.getLogger(__name__)

# ✅ Dummy config class
class RAGSearchConfig(BaseModel):
    pass

class RAGSearchComponent(DirectiveProvider, CommandProvider, ConfigurableComponent[RAGSearchConfig]):
    """Provides a command to search via local RAG API."""

    # ✅ Required by ConfigurableComponent
    config_class = RAGSearchConfig

    def __init__(self, config: Optional[RAGSearchConfig] = None):
        super().__init__(config)

    def get_resources(self) -> Iterator[str]:
        yield "Internal RAG-based search engine"

    def get_commands(self) -> Iterator[Command]:
        yield self.rag_search

    @command(
        ["rag_search", "ragweb"],
        "Searches internal knowledge base using RAG API",
        {
            "query": JSONSchema(
                type=JSONSchema.Type.STRING,
                description="The search query",
                required=True,
            )
        },
    )
    def rag_search(self, query: str) -> str:
        url = "http://172.17.0.1:3542/get_perplexica_answer"
        payload = {"query": query}

        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            output = response.json()

            answer = output.get("message", "[No message returned]")
            # sources = output.get("sources", [])

            if answer:
                logger.info(f"✅ RAG search successful: {answer}")
                return answer

            else:
                logger.warning("❌ No answer found in RAG response.")
                return "❌ [No answer found]"

        except Exception as e:
            logger.error(f"❌ RAG search failed: {e}")
            return "❌ [RAG search failed]"
