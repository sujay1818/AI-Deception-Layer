from langchain_core.prompts import PromptTemplate
from langchain_core.language_models import BaseLanguageModel
from langchain_openai import AzureChatOpenAI
from typing import Optional, Dict, Any
import os

# Initialize LLM (optional - can be None for static responses)
_llm: Optional[BaseLanguageModel] = None

def initialize_llm():
    """Initialize the LLM for AI-powered deception generation using Azure OpenAI."""
    global _llm
    azure_api_key = ""
    azure_endpoint = "https://deceptionlayer.openai.azure.com/"
    deployment_name = "deceptionlayer"  # Azure OpenAI deployment name
    api_version = "2025-06-01"  # Azure OpenAI API version
    
    if azure_api_key:
        try:
            _llm = AzureChatOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=azure_api_key,
                api_version=api_version,
                deployment_name=deployment_name,
                temperature=0.7
            )
            print(f"[DEBUG] Azure OpenAI LLM initialized successfully")
            print(f"[DEBUG] Endpoint: {azure_endpoint}")
            print(f"[DEBUG] Deployment Name: {deployment_name}")
            print(f"[DEBUG] API Version: {api_version}")
        except Exception as e:
            print(f"Warning: Could not initialize Azure OpenAI LLM: {e}")
            import traceback
            traceback.print_exc()
            _llm = None
    else:
        print("[DEBUG] Azure API key not provided, LLM not initialized")
        _llm = None
    return _llm

# LangChain Prompt Templates for different deception scenarios
ADMIN_DECEPTION_TEMPLATE = PromptTemplate(
    input_variables=["path", "ip", "user_agent", "method"],
    template="""You are a security honeypot system generating a deceptive response for an unauthorized access attempt.

Context:
- Path: {path}
- IP Address: {ip}
- User Agent: {user_agent}
- HTTP Method: {method}

Generate a realistic but deceptive HTML response that:
1. Appears to be a legitimate admin panel error page
2. Logs the unauthorized access attempt (make it seem like security is aware)
3. Discourages further attempts without revealing it's a honeypot
4. Maintains a professional, corporate appearance

Return only the HTML content (no markdown, no code blocks)."""
)

LOGIN_DECEPTION_TEMPLATE = PromptTemplate(
    input_variables=["path", "ip", "user_agent", "method"],
    template="""You are a security honeypot system generating a deceptive JSON response for a login attempt.

Context:
- Path: {path}
- IP Address: {ip}
- User Agent: {user_agent}
- HTTP Method: {method}

Generate a realistic but deceptive JSON error response that:
1. Appears to be a legitimate authentication system error
2. Suggests the credentials were invalid (not that it's a honeypot)
3. May include subtle delay hints to slow down brute force attempts
4. Looks like a real API error response

Return only valid JSON (no markdown, no code blocks)."""
)

GENERIC_DECEPTION_TEMPLATE = PromptTemplate(
    input_variables=["path", "ip", "user_agent", "method"],
    template="""You are a security honeypot system generating a deceptive response for a generic endpoint access.

Context:
- Path: {path}
- IP Address: {ip}
- User Agent: {user_agent}
- HTTP Method: {method}

Generate a realistic but deceptive response that:
1. Appears to be a normal service response
2. Doesn't reveal it's a honeypot
3. Provides minimal information
4. Maintains the appearance of a legitimate service

Return only the text content (no markdown, no code blocks)."""
)

def _generate_ai_response(template: PromptTemplate, context: Dict[str, Any]) -> str:
    """Generate AI-powered deception response using LangChain template."""
    global _llm
    
    print(f"[DEBUG] _generate_ai_response called, _llm is None: {_llm is None}")
    
    # Auto-initialize LLM if not already initialized
    if _llm is None:
        print("[DEBUG] LLM not initialized, attempting to initialize...")
        initialize_llm()
        if _llm is None:
            print("[DEBUG] LLM initialization failed, returning None")
            return None
        print("[DEBUG] LLM initialized successfully")
    
    try:
        print("[DEBUG] Formatting prompt with context...")
        # Format the prompt with context
        formatted_prompt = template.format(
            path=context.get("path", "unknown"),
            ip=context.get("ip", "unknown"),
            user_agent=context.get("user_agent", "unknown"),
            method=context.get("method", "GET")
        )
        
        print("[DEBUG] Invoking LLM...")
        # Generate response using LLM
        response = _llm.invoke(formatted_prompt)
        print(f"[DEBUG] LLM response type: {type(response)}")
        print(f"[DEBUG] LLM response: {response}")
        
        # Handle both string and AIMessage responses
        if hasattr(response, 'content'):
            print(f"[DEBUG] Response has 'content' attribute: {response.content.strip()}")
            return response.content.strip()
        print(f"[DEBUG] Response as string: {str(response).strip()}")
        return str(response).strip()
    except Exception as e:
        print(f"[DEBUG] Error generating AI response: {e}")
        import traceback
        traceback.print_exc()
        return None

def generate_deception(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate deception response using LangChain templates and optional AI.
    
    Args:
        context: Dictionary containing request context (path, ip, user_agent, method, etc.)
    
    Returns:
        Dictionary with response_type, content, status_code, and deception_id
    """
    path = context.get("path")
    
    # Try to generate AI response first, fall back to static if LLM not available
    ai_content = None
    
    if path == "/admin":
        ai_content = _generate_ai_response(ADMIN_DECEPTION_TEMPLATE, context)
        
        if ai_content:
            content = ai_content
        else:
            # Fallback to static response
            content = "<h1>Admin Panel</h1><p>Unauthorized access logged.</p>"
        
        return {
            "response_type": "html",
            "content": content,
            "status_code": 403,
            "deception_id": "dec-admin-001"
        }
    
    if path == "/login":
        ai_content = _generate_ai_response(LOGIN_DECEPTION_TEMPLATE, context)
        
        if ai_content:
            try:
                import json
                # Try to parse as JSON, if not valid JSON, wrap it
                content = json.loads(ai_content)
            except:
                content = {"error": ai_content}
        else:
            # Fallback to static response
            content = {"error": "Invalid credentials"}
        
        return {
            "response_type": "json",
            "content": content,
            "status_code": 401,
            "deception_id": "dec-login-001"
        }
    
    # Generic endpoint
    ai_content = _generate_ai_response(GENERIC_DECEPTION_TEMPLATE, context)
    
    if ai_content:
        content = ai_content
    else:
        # Fallback to static response
        content = "OK"
    
    return {
        "response_type": "text",
        "content": content,
        "status_code": 200,
        "deception_id": "dec-generic-001"
    }
