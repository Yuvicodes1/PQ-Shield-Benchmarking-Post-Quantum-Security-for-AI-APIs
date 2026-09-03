"""Real streaming backend using Hugging Face `transformers`.

NOT installed by default -- transformers + torch are large dependencies the
core crypto benchmark doesn't need. Install and configure with:

    pip install -r requirements-streaming.txt
    export PQ_SHIELD_STREAMING_BACKEND=transformers
    export PQ_SHIELD_HF_MODEL=meta-llama/Llama-3.2-1B-Instruct   # or a local path

Loading a model by hub id downloads it from huggingface.co on first use --
this requires network access this project's own development sandbox does
not have, so this backend is meant to run on your own machine. A locally
downloaded model directory works identically; just point PQ_SHIELD_HF_MODEL
at that directory instead of a hub id.

This backend performs genuine LLM inference -- its timing is measured from
real generation, not simulated. CPU inference works but is slow for
anything above ~1-3B parameters; set PQ_SHIELD_HF_DEVICE=cuda if you have a
GPU available.
"""

from __future__ import annotations

import os
import threading

from .base import StreamingBackend


class TransformersStreamingBackend(StreamingBackend):
    name = "transformers"
    real_inference = True

    def __init__(self, model_name: str | None = None, device: str | None = None):
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer, TextIteratorStreamer
        except ImportError as exc:
            raise RuntimeError(
                "transformers/torch are not installed. Run:\n"
                "    pip install -r requirements-streaming.txt\n"
                "See docs/STREAMING.md for setup details."
            ) from exc

        self._TextIteratorStreamer = TextIteratorStreamer

        model_name = model_name or os.environ.get("PQ_SHIELD_HF_MODEL", "meta-llama/Llama-3.2-1B-Instruct")
        device = device or os.environ.get("PQ_SHIELD_HF_DEVICE", "cpu")

        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModelForCausalLM.from_pretrained(
            model_name, torch_dtype=torch.float32, device_map=device
        )
        self._device = device

    def stream(self, prompt: str, max_tokens: int):
        messages = [{"role": "user", "content": prompt}]
        inputs = self._tokenizer.apply_chat_template(
            messages, return_tensors="pt", add_generation_prompt=True
        ).to(self._device)

        streamer = self._TextIteratorStreamer(
            self._tokenizer, skip_prompt=True, skip_special_tokens=True
        )
        generate_kwargs = dict(input_ids=inputs, max_new_tokens=max_tokens, streamer=streamer)

        # generate() blocks until done; run it in a background thread so the
        # streamer can be consumed incrementally by this generator instead.
        thread = threading.Thread(target=self._model.generate, kwargs=generate_kwargs)
        thread.start()
        for text in streamer:
            if text:
                yield text
        thread.join()
