"""Pure Python text similarity for scam pattern matching."""

from difflib import SequenceMatcher


def compute_similarity(text_a: str, text_b: str) -> float:
    """Return a 0.0-1.0 similarity ratio between two texts."""
    return SequenceMatcher(None, text_a.lower(), text_b.lower()).ratio()


def filter_by_similarity(
    candidates: list, query_text: str, threshold: float, text_field: str = "inputText"
) -> list:
    """Filter candidate documents by text similarity above threshold.

    Returns list of dicts with added 'similarity' field, sorted desc.
    """
    results = []
    for doc in candidates:
        score = compute_similarity(query_text, doc.get(text_field, ""))
        if score >= threshold:
            results.append({**doc, "similarity": round(score, 3)})
    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results
