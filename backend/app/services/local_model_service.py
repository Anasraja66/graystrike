"""
GrayStrike Local & HuggingFace Model Inference Service
Provides offline/local LLM synthesis for Llama and DeepSeek models:
- Hugging Face Inference API / Serverless (using HF_TOKEN)
- Local Ollama / vLLM Air-Gapped Endpoint (zero API attack vectors)
- Seamless fallback to Deterministic Synthesis Oracle
"""
import os
import json
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

try:
    from huggingface_hub import InferenceClient
    HAS_HF = True
except ImportError:
    HAS_HF = False

import httpx

logger = logging.getLogger("graystrike.local_model")


class LocalModelService:
    """
    Orchestrates Local Llama & DeepSeek models for vulnerability patch generation.
    Supports complete air-gapped offline operation to eliminate external API attack vectors.
    """

    def __init__(self):
        self.hf_token = os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACE_API_KEY")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self.default_model = os.getenv("LOCAL_MODEL_NAME", "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B")
        self.hf_client: Optional[Any] = None

        if HAS_HF and self.hf_token:
            try:
                self.hf_client = InferenceClient(token=self.hf_token)
            except Exception as e:
                logger.warning(f"Could not initialize HF InferenceClient: {e}")

    def synthesize_remediation_hypothesis(
        self,
        vulnerable_code: str,
        buggy_statement: str,
        cwe_id: str,
        fault_type: str,
        counterexample: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Synthesizes a minimal surgical patch candidate using local Llama / DeepSeek model.
        If offline Ollama is reachable, uses local air-gapped inference;
        otherwise leverages Hugging Face InferenceClient with HF_TOKEN.
        """
        system_prompt = (
            "You are GrayStrike Neuro-Symbolic Remediation Core. "
            "Given a vulnerable code snippet, output ONLY the single replacement statement "
            "that fixes the vulnerability without introducing external functions or variables. "
            "Do not explain. Output raw replacement code only."
        )

        user_prompt = f"Vulnerable File:\n{vulnerable_code}\n\nFault: {fault_type} ({cwe_id})\nBuggy Line: {buggy_statement}\n"
        if counterexample:
            user_prompt += f"SMT Counterexample: {counterexample}\nEnsure exploit state is strictly eliminated."

        # 1. Try Local Air-gapped Ollama if running
        ollama_result = self._try_ollama_generate(system_prompt, user_prompt)
        if ollama_result:
            return {
                "source": "local_ollama_offline",
                "model": "deepseek-coder / llama3",
                "candidate_patch": ollama_result,
                "air_gapped": True
            }

        # 2. Try Hugging Face Client with HF_TOKEN
        if self.hf_client:
            hf_result = self._try_hf_inference(system_prompt, user_prompt)
            if hf_result:
                return {
                    "source": "huggingface_hub",
                    "model": self.default_model,
                    "candidate_patch": hf_result,
                    "air_gapped": False
                }

        # 3. Deterministic Verified Grammar Baseline
        return {
            "source": "deterministic_grammar_oracle",
            "model": "symbolic_rule_lattice",
            "candidate_patch": None,
            "air_gapped": True
        }

    def _try_ollama_generate(self, system: str, prompt: str) -> Optional[str]:
        """Queries local Ollama endpoint if running on localhost."""
        try:
            with httpx.Client(timeout=2.0) as client:
                res = client.post(
                    f"{self.ollama_base_url}/api/generate",
                    json={
                        "model": "deepseek-coder",
                        "prompt": f"{system}\n\n{prompt}",
                        "stream": False
                    }
                )
                if res.status_code == 200:
                    data = res.json()
                    return data.get("response", "").strip()
        except Exception:
            pass
        return None

    def _try_hf_inference(self, system: str, prompt: str) -> Optional[str]:
        """Queries Hugging Face model using HF_TOKEN."""
        try:
            if not self.hf_client:
                return None
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
            response = self.hf_client.chat.completions.create(
                model=self.default_model,
                messages=messages,
                max_tokens=150,
                temperature=0.1
            )
            content = response.choices[0].message.content
            return content.strip()
        except Exception as e:
            logger.info(f"HF Inference skipped or offline: {e}")
            return None


local_model_service = LocalModelService()
