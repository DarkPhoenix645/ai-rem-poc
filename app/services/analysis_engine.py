import asyncio
import json
import logging
from typing import Dict, List, Optional, Union

import anthropic
import instructor
import openai
from openai import OpenAI
from pydantic import ValidationError

from app.config import get_settings
from app.models.core import Finding, PolicyContext, AnalysisRequest
from app.services.rag_service import RAGService
from app.services.cache_service import CacheService
from app.services.heuristics import HeuristicsEngine
from app.prompts.prompt_manager import prompt_manager

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Core AI analysis engine that processes IAM policies using LLMs
    enhanced with RAG context and structured output enforcement.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.rag_service = RAGService()
        self.cache_service = CacheService()
        self.heuristics_engine = HeuristicsEngine()
        
        # Initialize LLM clients
        self._init_llm_clients()
    
    def _init_llm_clients(self):
        """Initialize LLM clients with instructor for structured outputs"""
        # Primary LLM (Anthropic Claude)
        if self.settings.anthropic_api_key:
            anthropic_client = anthropic.Anthropic(
                api_key=self.settings.anthropic_api_key
            )
            self.primary_llm = instructor.from_anthropic(anthropic_client)
            logger.info("Initialized Anthropic Claude client")
        else:
            self.primary_llm = None
            logger.warning("Anthropic API key not provided")
        
        # Fallback LLM (OpenAI GPT-4)
        if self.settings.openai_api_key:
            openai_client = OpenAI(api_key=self.settings.openai_api_key)
            self.fallback_llm = instructor.from_openai(openai_client)
            logger.info("Initialized OpenAI GPT-4 client")
        else:
            self.fallback_llm = None
            logger.warning("OpenAI API key not provided")
    
    async def analyze_policy(self, request: AnalysisRequest) -> Finding:
        """
        Main analysis method that processes a single IAM policy.
        
        Args:
            request: Analysis request containing policy and context
            
        Returns:
            Finding: Structured security finding
        """
        try:
            # Check cache first
            cache_key = self._generate_cache_key(request.policy_document)
            cached_finding = await self.cache_service.get_finding(cache_key)
            
            if cached_finding:
                logger.info(f"Cache hit for policy: {cache_key[:8]}...")
                return cached_finding
            
            # Get RAG context
            rag_context = await self.rag_service.get_policy_specific_context(
                request.policy_document
            )
            
            # Perform AI analysis
            finding = await self._analyze_with_llms(
                request.policy_document,
                request.context,
                rag_context
            )
            
            # Cache the result
            await self.cache_service.store_finding(cache_key, finding)
            
            return finding
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            # Fallback to heuristics
            return await self._fallback_analysis(request)
    
    async def _analyze_with_llms(
        self, 
        policy_document: dict, 
        context: PolicyContext,
        rag_context: str
    ) -> Finding:
        """
        Attempt analysis with LLMs in order of preference.
        Uses instructor to guarantee structured output.
        """
        
        # Build the prompt using consolidated prompt templates
        prompt = prompt_manager.get_analysis_prompt(policy_document, context.__dict__, rag_context)
        
        # Try primary LLM first
        if self.primary_llm:
            try:
                return await self._query_claude(prompt)
            except Exception as e:
                logger.warning(f"Primary LLM failed: {e}")
        
        # Try fallback LLM
        if self.fallback_llm:
            try:
                return await self._query_openai(prompt)
            except Exception as e:
                logger.warning(f"Fallback LLM failed: {e}")
        
        raise Exception("All LLMs failed")
    
    async def _query_claude(self, prompt: str) -> Finding:
        """Query Claude with structured output enforcement"""
        try:
            response = await asyncio.to_thread(
                self.primary_llm.messages.create,
                model=self.settings.anthropic_model,
                response_model=Finding,
                max_tokens=self.settings.anthropic_max_tokens,
                temperature=self.settings.anthropic_temperature,
                max_retries=self.settings.max_retries,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            logger.info("Successfully analyzed with Claude")
            return response
            
        except Exception as e:
            logger.error(f"Claude analysis failed: {e}")
            raise
    
    async def _query_openai(self, prompt: str) -> Finding:
        """Query OpenAI with structured output enforcement"""
        try:
            response = await asyncio.to_thread(
                self.fallback_llm.chat.completions.create,
                model=self.settings.openai_model,
                response_model=Finding,
                max_tokens=self.settings.openai_max_tokens,
                temperature=self.settings.openai_temperature,
                max_retries=self.settings.max_retries,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            logger.info("Successfully analyzed with GPT-4o")
            return response
            
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            raise
    
    
    def _generate_cache_key(self, policy_document: dict) -> str:
        """Generate a deterministic cache key for a policy"""
        import hashlib
        
        # Create canonical representation
        canonical = json.dumps(policy_document, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    async def _fallback_analysis(self, request: AnalysisRequest) -> Finding:
        """Fallback to heuristics when LLMs fail"""
        logger.info("Using heuristics fallback")
        return await self.heuristics_engine.analyze(request)


# Singleton instance
analysis_engine = AnalysisEngine()
