"""
Pure-Python Okapi BM25 (`rank_bm25`) implementation for OpenBSD WASM64 (`devel/swival`).
Implements `BM25Okapi` without NumPy/C-extension dependencies.
"""
from __future__ import annotations

import math
from typing import Callable, Dict, List, Optional, Sequence, TypeVar

T = TypeVar("T")


class BM25Okapi:
    def __init__(
        self,
        corpus: Sequence[Sequence[str]],
        tokenizer: Optional[Callable[[str], List[str]]] = None,
        k1: float = 1.5,
        b: float = 0.75,
        epsilon: float = 0.25,
    ) -> None:
        self.k1 = float(k1)
        self.b = float(b)
        self.epsilon = float(epsilon)
        self.corpus_size = len(corpus)
        self.doc_freqs: List[Dict[str, int]] = []
        self.idf: Dict[str, float] = {}
        self.doc_len: List[int] = []

        nd: Dict[str, int] = {}
        num_doc = 0
        for document in corpus:
            tokens = tokenizer(document) if (tokenizer and isinstance(document, str)) else list(document)
            self.doc_len.append(len(tokens))
            num_doc += len(tokens)
            frequencies: Dict[str, int] = {}
            for word in tokens:
                frequencies[word] = frequencies.get(word, 0) + 1
            self.doc_freqs.append(frequencies)
            for word in frequencies:
                nd[word] = nd.get(word, 0) + 1

        self.avgdl = (num_doc / self.corpus_size) if self.corpus_size > 0 else 0.0
        idf_sum = 0.0
        negative_idfs: List[str] = []
        for word, freq in nd.items():
            idf_val = math.log(self.corpus_size - freq + 0.5) - math.log(freq + 0.5)
            self.idf[word] = idf_val
            idf_sum += idf_val
            if idf_val < 0:
                negative_idfs.append(word)

        self.average_idf = (idf_sum / len(self.idf)) if self.idf else 0.0
        eps = self.epsilon * self.average_idf
        for word in negative_idfs:
            self.idf[word] = eps

    def get_scores(self, query: Sequence[str]) -> List[float]:
        scores = [0.0] * self.corpus_size
        if not self.corpus_size or self.avgdl == 0.0:
            return scores
        for q in query:
            idf = self.idf.get(q)
            if idf is None:
                continue
            for idx in range(self.corpus_size):
                q_freq = self.doc_freqs[idx].get(q, 0)
                if q_freq == 0:
                    continue
                dl = self.doc_len[idx]
                denom = q_freq + self.k1 * (1.0 - self.b + self.b * dl / self.avgdl)
                scores[idx] += idf * (q_freq * (self.k1 + 1.0) / denom)
        return scores

    def get_top_n(self, query: Sequence[str], documents: Sequence[T], n: int = 5) -> List[T]:
        if len(documents) != self.corpus_size:
            raise ValueError("The documents given don't match the index corpus!")
        scores = self.get_scores(query)
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:n]
        return [documents[i] for i in ranked]
