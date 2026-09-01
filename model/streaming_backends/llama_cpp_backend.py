"""Real streaming backend using llama-cpp-python against a local GGUF model
file.

NOT installed by default -- llama-cpp-python compiles a C++ extension and is
a meaningfully heavy dependency for a project whose core crypto benchmark
doesn't need it. A bare `pip install llama-cpp-python` compiles CPU-only on
every platform; GPU acceleration (Metal on Apple Silicon, CUDA on Nvidia)
requires an explicit build flag at install time -- see
docs/STREAMING.md "Setting up a real model backend" for exact commands per
platform. Getting this wrong doesn't error, it just silently runs on CPU,
which is why n_gpu_layers is exposed and defaulted to "offload everything"
below rather than left at the library's own CPU-only default.

    pip install -r requirements-streaming.txt   # see docs/STREAMING.md for GPU build flags
    export PQ_SHIELD_STREAMING_BACKEND=llama_cpp
    export PQ_SHIELD_LLAMA_MODEL_PATH=/path/to/model.gguf

This backend performs genuine LLM inference -- its timing is measured from
real generation, not simulated.
"""

from __future__ import annotations

import os

from .base import StreamingBackend


class LlamaCppStreamingBackend(StreamingBackend):
    name = "llama_cpp"
    real_inference = True

    def __init__(
        self,
        model_path: str | None = None,
        n_ctx: int = 4096,
        n_threads: int | None = None,
        n_gpu_layers: int | None = None,
    ):
        try:
            from llama_cpp import Llama
        except ImportError as exc:
            raise RuntimeError(
                "llama-cpp-python is not installed. Run:\n"
                "    pip install -r requirements-streaming.txt\n"
                "See docs/STREAMING.md for setup details."
            ) from exc

        model_path = model_path or os.environ.get("PQ_SHIELD_LLAMA_MODEL_PATH")
        if not model_path:
            raise RuntimeError(
                "PQ_SHIELD_LLAMA_MODEL_PATH is not set. Point it at a local .gguf file, e.g.:\n"
                "    export PQ_SHIELD_LLAMA_MODEL_PATH=/path/to/llama-3.2-3b-instruct-q4_k_m.gguf"
            )
        if not os.path.isfile(model_path):
            raise RuntimeError(f"PQ_SHIELD_LLAMA_MODEL_PATH does not point to a file: {model_path!r}")

        # -1 = offload every layer to GPU (Metal or CUDA, whichever this
        # build of llama-cpp-python was compiled with). Silently has no
        # effect -- not an error -- on a CPU-only build, so this default is
        # safe even if GPU support isn't actually compiled in; but it means
        # a CPU-only build will never *tell you* it's ignoring this, which
        # is exactly why docs/STREAMING.md tells you to verify GPU offload
        # actually happened (llama_supports_gpu_offload()) rather than
        # trusting that setting this flag was sufficient.
        n_gpu_layers = (
            n_gpu_layers
            if n_gpu_layers is not None
            else int(os.environ.get("PQ_SHIELD_LLAMA_GPU_LAYERS", "-1"))
        )

        self._llm = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_threads=n_threads,  # None = let llama.cpp pick based on host CPU
            n_gpu_layers=n_gpu_layers,
            verbose=False,
        )

    def stream(self, prompt: str, max_tokens: int):
        # Generic instruction-style framing; works reasonably across most
        # small instruct-tuned GGUF models without needing per-model chat
        # templates. Swap for a model-specific template if you need exact
        # fidelity to that model's training format.
        formatted = f"<|user|>\n{prompt}\n<|assistant|>\n"
        for chunk in self._llm(formatted, max_tokens=max_tokens, stream=True):
            text = chunk["choices"][0]["text"]
            if text:
                yield text
