import logging
import os
from typing import Any, List, Optional
import numpy as np
from numpy.typing import NDArray

logger = logging.getLogger("prospector-lite.embeddings")

_MODEL_CACHE = {}


class TransformerEmbedder:
    def __init__(self, model_name_or_path: str):
        import torch
        from transformers import AutoModel, AutoTokenizer

        # Standardize HuggingFace name if shorthand passed
        if model_name_or_path == "all-MiniLM-L6-v2":
            model_name_or_path = "sentence-transformers/all-MiniLM-L6-v2"
        elif model_name_or_path.startswith(("/", "./", "../")):
            if not os.path.isdir(model_name_or_path):
                # Check if it was downloaded into a models/ subfolder
                possible_path = os.path.join(os.path.dirname(model_name_or_path), "models", os.path.basename(model_name_or_path))
                if os.path.isdir(possible_path):
                    model_name_or_path = possible_path
                else:
                    raise FileNotFoundError(f"Local model directory not found: {model_name_or_path}")

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
        self.model = AutoModel.from_pretrained(model_name_or_path).to(self.device)
        self.model.eval()

    def _mean_pooling(self, model_output, attention_mask):
        import torch
        token_embeddings = model_output[0]
        input_mask_expanded = (
            attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
        )
        return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(
            input_mask_expanded.sum(1), min=1e-9
        )

    def encode(
        self,
        texts: List[str],
        batch_size: int = 16,
        show_progress: bool = False,
        num_commits: int = 0,
    ) -> NDArray[Any]:
        import sys
        import torch
        import torch.nn.functional as F

        all_embeddings = []
        total = len(texts)

        for i in range(0, total, batch_size):
            batch = texts[i : i + batch_size]
            encoded_input = self.tokenizer(
                batch, padding=True, truncation=True, max_length=512, return_tensors="pt"
            ).to(self.device)

            with torch.no_grad():
                model_output = self.model(**encoded_input)

            sentence_embeddings = self._mean_pooling(
                model_output, encoded_input["attention_mask"]
            )
            normalized = F.normalize(sentence_embeddings, p=2, dim=1)
            all_embeddings.append(normalized.cpu().numpy())

            if show_progress:
                done = min(i + len(batch), total)
                pct = int((done / total) * 100)
                commits_info = f" ({num_commits} commits)" if num_commits else ""
                sys.stderr.write(f"\r-> [3/3] Computing embeddings: [ {done} / {total} chunks{commits_info} ] ({pct}%)")
                sys.stderr.flush()

        if show_progress and total > 0:
            sys.stderr.write(" [Done]\n")

        dim = getattr(self.model.config, "hidden_size", 384)
        return np.vstack(all_embeddings) if all_embeddings else np.empty((0, dim), dtype=np.float32)


def get_embedding_model(model_name_or_path: str = "sentence-transformers/all-MiniLM-L6-v2", show_progress: bool = False):
    if model_name_or_path in _MODEL_CACHE:
        return _MODEL_CACHE[model_name_or_path]

    if show_progress:
        import sys
        sys.stderr.write(f"-> Loading transformer embedding model ({model_name_or_path})... ")
        sys.stderr.flush()

    embedder = TransformerEmbedder(model_name_or_path)
    _MODEL_CACHE[model_name_or_path] = embedder

    if show_progress:
        import sys
        sys.stderr.write("[Done]\n")

    return embedder


SOURCE_EXTENSIONS = {
    ".rs", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".py", ".go",
    ".java", ".js", ".ts", ".rb", ".php", ".swift", ".sh"
}

IGNORE_FILE_PATTERNS = ["test", "benches", "doc", "cargo.lock", "readme", ".md"]


def is_source_file(filename: str) -> bool:
    f_lower = filename.lower()
    base = os.path.basename(f_lower)
    _, ext = os.path.splitext(base)
    if ext not in SOURCE_EXTENSIONS:
        return False
    # Avoid pure test files if possible
    if any(p in f_lower for p in ["/tests/", "/benches/", "test_"]):
        return False
    return True


def extract_source_chunks_from_diff(commit, advisory) -> List[str]:
    """
    Split the commit diff by file, prioritizing actual source code files
    over test cases, lockfiles, or markdown.
    """
    if not commit.diff:
        return []

    file_diffs = {}
    current_file = None
    current_lines = []

    for line in commit.diff:
        if line.startswith("diff --git "):
            if current_file and current_lines:
                file_diffs[current_file] = current_lines
            parts = line.split()
            current_file = parts[-1].lstrip("b/") if len(parts) >= 4 else "unknown"
            current_lines = []
        else:
            current_lines.append(line)

    if current_file and current_lines:
        file_diffs[current_file] = current_lines

    # Sort files: source files first, especially files matching advisory filenames!
    def file_priority(fname: str) -> int:
        f_lower = fname.lower()
        score = 0
        if is_source_file(fname):
            score += 10
        # Check if file matches advisory mentioned files
        for adv_file in advisory.files:
            if adv_file.lower() in f_lower:
                score += 50
        # Deprioritize tests/docs
        if any(p in f_lower for p in IGNORE_FILE_PATTERNS):
            score -= 20
        return score

    sorted_files = sorted(file_diffs.keys(), key=file_priority, reverse=True)

    chunks = []
    # Build text representation for the best source files
    for fname in sorted_files[:3]:  # inspect up to 3 best source files
        added_lines = [
            line[1:].strip()
            for line in file_diffs[fname]
            if line.startswith("+") and not line.startswith("+++") and len(line.strip()) > 3
        ]
        if added_lines:
            chunk = (
                f"Commit message: {commit.message}\n"
                f"File modified: {fname}\n"
                f"Code patch:\n" + "\n".join(added_lines[:25])
            )
            chunks.append(chunk)

    if not chunks:
        # Fallback to general message + files
        chunks.append(f"Commit message: {commit.message}\nChanged files: {', '.join(commit.changed_files[:10])}")

    return chunks


def build_advisory_text(advisory) -> str:
    parts = []
    if advisory.package_name:
        parts.append(f"Package: {advisory.package_name}")
    if advisory.summary:
        parts.append(f"Summary: {advisory.summary}")
    if advisory.description:
        parts.append(f"Details: {advisory.description}")
    return "\n".join(parts)


def apply_semantic_embeddings(
    advisory,
    candidates: list,
    model_name_or_path: str = "sentence-transformers/all-MiniLM-L6-v2",
    top_n_to_rerank: Optional[int] = 50,
    similarity_threshold: float = 0.40,
    max_boost: int = 50,
    show_progress: bool = False,
):
    if not candidates:
        return

    model = get_embedding_model(model_name_or_path, show_progress=show_progress)

    adv_text = build_advisory_text(advisory)
    adv_vec = model.encode([adv_text], show_progress=False)[0]

    target_commits = candidates[:top_n_to_rerank] if top_n_to_rerank else candidates

    # Build chunks for each commit (handles multi-file commits so file 3 isn't missed)
    commit_chunk_map = []
    flat_texts = []
    for c in target_commits:
        chunks = extract_source_chunks_from_diff(c, advisory)
        start_idx = len(flat_texts)
        flat_texts.extend(chunks)
        commit_chunk_map.append((start_idx, len(chunks)))

    # Encode in batches of 16 (prevents memory spikes)
    chunk_vecs = model.encode(
        flat_texts,
        batch_size=16,
        show_progress=show_progress,
        num_commits=len(target_commits),
    )

    # Compute similarities against advisory vector
    chunk_sims = np.dot(chunk_vecs, adv_vec)

    for i, commit in enumerate(target_commits):
        start_idx, num_chunks = commit_chunk_map[i]
        # Max-pool across the commit's source files (so if file 3 is the fix, its high match wins)
        best_sim = float(np.max(chunk_sims[start_idx : start_idx + num_chunks]))

        if best_sim >= similarity_threshold:
            scale = (best_sim - similarity_threshold) / (1.0 - similarity_threshold)
            boost = int(round(scale * max_boost))
            if boost > 0:
                commit.score += boost
                commit.matched_rules.append({
                    "rule": "SEMANTIC_SIMILARITY",
                    "weight": boost,
                    "reason": f"Semantic cosine similarity: {best_sim:.3f}",
                })
