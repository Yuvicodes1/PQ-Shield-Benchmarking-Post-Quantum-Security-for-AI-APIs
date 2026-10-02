"""Network-condition emulator: a TCP proxy that adds propagation delay and a
bandwidth bottleneck between the load generator and the server.

Every other PQ-Shield measurement runs over loopback, where a 1,088-byte
ML-KEM ciphertext or a 3,309-byte ML-DSA signature costs essentially nothing
to move -- which is exactly where post-quantum's larger messages would show
up on a real network. This proxy puts a configurable path in between:

  * one-way propagation delay = rtt_ms / 2, applied in each direction;
  * a bottleneck of `bandwidth_mbps` per direction, shared by all connections
    through the proxy (serialization delay = bytes * 8 / bandwidth, queued
    behind whatever is already in flight on that direction).

Bytes are released strictly in order per direction, so HTTP semantics are
untouched. What it does NOT model: TCP slow start / initial congestion
window, packet loss and retransmission, or MTU fragmentation -- it shapes the
byte stream above TCP, not packets. Those effects make large handshakes cost
*more* than modeled here, so results are a lower bound on PQC's network cost
(state this in the paper). Linux `tc netem` would model them, but needs root
and isn't available on macOS; this runs anywhere, unprivileged.

Usage (normally started by bench.orchestrator --network-profile):
    python -m bench.netem_proxy --listen-port 9000 --upstream-port 8000 --rtt-ms 50 --bandwidth-mbps 20
"""

from __future__ import annotations

import argparse
import asyncio
import time

# Illustrative access-network profiles (RTT, per-direction bottleneck).
NETWORK_PROFILES: dict[str, dict | None] = {
    "localhost": None,                                  # no proxy: loopback, the default everywhere else
    "metro": {"rtt_ms": 10, "bandwidth_mbps": 100},     # same-region cloud / good broadband
    "wan": {"rtt_ms": 50, "bandwidth_mbps": 20},        # cross-country / typical home broadband
    "mobile": {"rtt_ms": 100, "bandwidth_mbps": 5},     # congested 4G-class link
}


class Link:
    """One direction of the emulated path, shared by all connections."""

    def __init__(self, one_way_delay_s: float, bandwidth_bps: float):
        self.delay = one_way_delay_s
        self.bw = bandwidth_bps
        self.tx_free = 0.0  # monotonic time at which the bottleneck is next idle

    def release_time(self, nbytes: int) -> float:
        now = time.monotonic()
        start = max(now, self.tx_free)
        self.tx_free = start + (nbytes * 8 / self.bw if self.bw > 0 else 0.0)
        return self.tx_free + self.delay


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, link: Link) -> None:
    queue: asyncio.Queue = asyncio.Queue()

    async def deliver() -> None:
        try:
            while (item := await queue.get()) is not None:
                at, data = item
                wait = at - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    deliverer = asyncio.create_task(deliver())
    try:
        while data := await reader.read(65536):
            queue.put_nowait((link.release_time(len(data)), data))
    except (ConnectionError, OSError):
        pass
    finally:
        queue.put_nowait(None)
        await deliverer


async def serve(listen_port: int, upstream_host: str, upstream_port: int, rtt_ms: float, bandwidth_mbps: float) -> None:
    one_way = rtt_ms / 2000.0
    bw = bandwidth_mbps * 1e6
    uplink, downlink = Link(one_way, bw), Link(one_way, bw)  # client->server, server->client

    async def handle(c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter) -> None:
        try:
            s_reader, s_writer = await asyncio.open_connection(upstream_host, upstream_port)
        except OSError:
            c_writer.close()
            return
        await asyncio.gather(_pump(c_reader, s_writer, uplink), _pump(s_reader, c_writer, downlink))

    server = await asyncio.start_server(handle, "127.0.0.1", listen_port, backlog=2048)
    print(f"netem proxy :{listen_port} -> {upstream_host}:{upstream_port} "
          f"(rtt={rtt_ms} ms, bw={bandwidth_mbps} Mbit/s per direction)", flush=True)
    async with server:
        await server.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description="PQ-Shield network-condition emulating TCP proxy")
    ap.add_argument("--listen-port", type=int, required=True)
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--upstream-port", type=int, required=True)
    ap.add_argument("--rtt-ms", type=float, required=True)
    ap.add_argument("--bandwidth-mbps", type=float, required=True)
    args = ap.parse_args()
    asyncio.run(serve(args.listen_port, args.upstream_host, args.upstream_port, args.rtt_ms, args.bandwidth_mbps))


if __name__ == "__main__":
    main()
