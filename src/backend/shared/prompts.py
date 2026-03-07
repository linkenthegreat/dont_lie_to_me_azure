"""
Centralized prompt management for AI agents.

Loads system prompts from prompts.yaml at module import time.
Services use get_prompt() to retrieve prompt configuration with
automatic fallback to embedded defaults if YAML loading fails.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

_prompts: Optional[Dict[str, Any]] = None
_load_attempted = False


def _load_prompts() -> Dict[str, Any]:
    """
    Load prompts from prompts.yaml.

    Returns
    -------
    dict
        Parsed YAML content with prompt configurations.
        Returns empty dict if file not found or parsing fails.
    """
    try:
        import yaml
        
        # Path relative to this file: backend/shared/prompts.py -> backend/prompts.yaml
        prompts_path = Path(__file__).parent.parent / "prompts.yaml"
        
        if not prompts_path.exists():
            logger.warning(f"Prompts file not found at {prompts_path}. Services will use embedded fallback prompts.")
            return {}
        
        with open(prompts_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
            logger.info(f"Loaded {len(data)} prompt configurations from {prompts_path}")
            return data or {}
            
    except ImportError:
        logger.warning("PyYAML not installed. Services will use embedded fallback prompts. Install with: pip install pyyaml")
        return {}
    except Exception as e:
        logger.error(f"Failed to load prompts.yaml: {e}. Services will use embedded fallback prompts.")
        return {}


def get_prompt_config(key: str) -> Dict[str, Any]:
    """
    Retrieve prompt configuration by key.

    This function is called by service modules to get system prompts.
    If YAML loading failed or key not found, services should use their
    embedded fallback prompts.

    Parameters
    ----------
    key : str
        Prompt configuration key (e.g., 'scam_classifier').

    Returns
    -------
    dict
        Prompt configuration with keys like:
        - system_prompt: str
        - model: str (optional)
        - temperature: float (optional)
        - max_tokens: int (optional)
        Returns empty dict if key not found.

    Examples
    --------
    >>> config = get_prompt_config("scam_classifier")
    >>> system_prompt = config.get("system_prompt", EMBEDDED_FALLBACK)
    >>> model = config.get("model", "gpt-4o-mini")
    """
    global _prompts, _load_attempted
    
    # Load prompts once on first call
    if not _load_attempted:
        _prompts = _load_prompts()
        _load_attempted = True
    
    if _prompts is None:
        return {}
    
    return _prompts.get(key, {})


def reload_prompts() -> None:
    """
    Force reload of prompts.yaml.

    Useful for development/testing to refresh prompts without restarting.
    Production code typically doesn't need this.
    """
    global _prompts, _load_attempted
    _load_attempted = False
    _prompts = None
    # Next call to get_prompt_config will trigger reload
