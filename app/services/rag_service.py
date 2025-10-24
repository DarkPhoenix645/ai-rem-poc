import asyncio
import logging
from typing import List, Optional

import chromadb
from chromadb.config import Settings as ChromaSettings
from sentence_transformers import SentenceTransformer

from app.config import get_settings

logger = logging.getLogger(__name__)


class RAGService:
    """
    Retrieval Augmented Generation service for security knowledge base.
    Handles embedding, storage, and retrieval of security context.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.embedding_model = None
        self.chroma_client = None
        self.collection = None
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize ChromaDB client and embedding model"""
        try:
            # Initialize embedding model
            self.embedding_model = SentenceTransformer(
                self.settings.embedding_model
            )
            
            # Parse ChromaDB URL to extract host and port
            chromadb_url = self.settings.chromadb_url
            if chromadb_url.startswith('http://'):
                chromadb_url = chromadb_url[7:]  # Remove 'http://'
            elif chromadb_url.startswith('https://'):
                chromadb_url = chromadb_url[8:]  # Remove 'https://'
            
            # Split host and port
            if ':' in chromadb_url:
                host, port = chromadb_url.split(':')
                port = int(port)
            else:
                host = chromadb_url
                port = 8000  # Default ChromaDB port
            
            # Initialize ChromaDB client with error handling
            try:
                # No authentication - connect directly
                self.chroma_client = chromadb.HttpClient(
                    host=host,
                    port=port
                )
                
                # Test connection
                self.chroma_client.heartbeat()
                
                # Get or create collection
                try:
                    self.collection = self.chroma_client.get_collection(
                        name=self.settings.chromadb_collection
                    )
                    logger.info(f"Connected to existing collection: {self.settings.chromadb_collection}")
                except Exception:
                    self.collection = self.chroma_client.create_collection(
                        name=self.settings.chromadb_collection,
                        metadata={"description": "Security research and best practices"}
                    )
                    logger.info(f"Created new collection: {self.settings.chromadb_collection}")
                    
            except Exception as chroma_error:
                logger.warning(f"ChromaDB connection failed: {chroma_error}")
                logger.info("Falling back to in-memory storage for development")
                # Fallback to in-memory storage
                self.chroma_client = chromadb.Client()
                self.collection = self.chroma_client.create_collection(
                    name=self.settings.chromadb_collection,
                    metadata={"description": "Security research and best practices"}
                )
                
        except Exception as e:
            logger.error(f"Failed to initialize RAG service: {e}")
            # For development, we'll allow the service to start without ChromaDB
            self.chroma_client = None
            self.collection = None
    
    async def add_documents(self, documents: List[str], metadatas: List[dict], ids: List[str]):
        """Add documents to the knowledge base"""
        if not self.collection:
            logger.warning("ChromaDB not available, skipping document addition")
            return
            
        try:
            # Generate embeddings
            embeddings = self.embedding_model.encode(documents).tolist()
            
            # Add to ChromaDB
            self.collection.add(
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info(f"Added {len(documents)} documents to knowledge base")
            
        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            raise
    
    async def retrieve_context(self, query: str, k: Optional[int] = None) -> List[str]:
        """
        Retrieve relevant context for a query.
        
        Args:
            query: The query text (e.g., IAM policy content)
            k: Number of chunks to retrieve (default from config)
            
        Returns:
            List of relevant text chunks
        """
        if not self.collection:
            logger.warning("ChromaDB not available, returning empty context")
            return []
            
        try:
            k = k or self.settings.retrieval_k
            
            # Generate query embedding
            query_embedding = self.embedding_model.encode([query]).tolist()[0]
            
            # Query ChromaDB
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=k,
                include=["documents", "metadatas"]
            )
            
            # Extract documents
            if results['documents']:
                relevant_chunks = results['documents'][0]
                logger.info(f"Retrieved {len(relevant_chunks)} relevant chunks")
                return relevant_chunks
            
            return []
            
        except Exception as e:
            logger.error(f"Failed to retrieve context: {e}")
            return []
    
    async def retrieve_context_with_filters(self, query: str, filters: dict = None, k: Optional[int] = None) -> List[str]:
        """
        Retrieve relevant context for a query with metadata filters.
        
        Args:
            query: The query text (e.g., IAM policy content)
            filters: Metadata filters (e.g., {"compliance_framework": "CIS"})
            k: Number of chunks to retrieve (default from config)
            
        Returns:
            List of relevant text chunks
        """
        if not self.collection:
            logger.warning("ChromaDB not available, returning empty context")
            return []
            
        try:
            k = k or self.settings.retrieval_k
            
            # Generate query embedding
            query_embedding = self.embedding_model.encode([query]).tolist()[0]
            
            # Build where clause for filtering
            where_clause = {}
            if filters:
                for key, value in filters.items():
                    if isinstance(value, list):
                        where_clause[key] = {"$in": value}
                    else:
                        where_clause[key] = {"$eq": value}
            
            # Query ChromaDB with filters
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=k,
                where=where_clause if where_clause else None,
                include=["documents", "metadatas"]
            )
            
            # Extract documents
            if results['documents']:
                relevant_chunks = results['documents'][0]
                logger.info(f"Retrieved {len(relevant_chunks)} context chunks with filters: {filters}")
                return relevant_chunks
            else:
                logger.warning(f"No relevant context found with filters: {filters}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to retrieve context with filters: {e}")
            return []
    
    async def get_policy_specific_context(self, policy_document: dict) -> str:
        """
        Get context specifically relevant to an IAM policy.
        
        Args:
            policy_document: The IAM policy JSON
            
        Returns:
            Formatted context string for LLM
        """
        # Convert policy to searchable text
        policy_text = self._policy_to_text(policy_document)
        
        # Retrieve relevant chunks
        chunks = await self.retrieve_context(policy_text)
        
        if not chunks:
            return "No specific security context found for this policy type."
        
        # Format for LLM consumption
        formatted_context = "\n\n".join([
            f"Security Knowledge #{i+1}:\n{chunk}"
            for i, chunk in enumerate(chunks)
        ])
        
        return formatted_context
    
    def _policy_to_text(self, policy_document: dict) -> str:
        """Convert IAM policy to searchable text"""
        text_parts = []
        
        if 'Statement' in policy_document:
            for stmt in policy_document['Statement']:
                # Extract actions
                if 'Action' in stmt:
                    actions = stmt['Action'] if isinstance(stmt['Action'], list) else [stmt['Action']]
                    text_parts.extend(actions)
                
                # Extract resources
                if 'Resource' in stmt:
                    resources = stmt['Resource'] if isinstance(stmt['Resource'], list) else [stmt['Resource']]
                    text_parts.extend(resources)
                
                # Extract effect
                if 'Effect' in stmt:
                    text_parts.append(stmt['Effect'])
        
        return " ".join(text_parts)


# Singleton instance
rag_service = RAGService()
