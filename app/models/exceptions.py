"""Custom exceptions for the IAM scanner application."""


class IAMScannerException(Exception):
    """Base exception for IAM scanner errors."""
    pass


class AnalysisError(IAMScannerException):
    """Raised when policy analysis fails."""
    pass


class AWSConnectionError(IAMScannerException):
    """Raised when AWS connection fails."""
    pass


class CacheError(IAMScannerException):
    """Raised when caching operations fail."""
    pass


class RAGError(IAMScannerException):
    """Raised when RAG operations fail."""
    pass


class LLMError(IAMScannerException):
    """Raised when LLM operations fail."""
    pass
