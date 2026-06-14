# dogecoin_qpu

**Dogecoin, and the eye that reads quipu.**

A thin fork of Dogecoin Core (v1.14.9). One addition: a keyless read-index for
*quipu* — multi-strand OP_RETURN inscriptions on the Dogecoin chain. This is the
node half of the [Colegio Invisible](https://github.com/ProfDoeg/colegio)
protocol; the client half holds the keys, builds, signs, and interprets.

```
  cinv keys · colegio · pydoge          client — compose · sign · interpret · sell
        │ quipuread (data in) · sendrawtransaction (txs out)
  dogecoin_qpu                          node — ACCESS data · BROADCAST · no keys
```

## Doctrine

The node **accesses data and broadcasts. Nothing else.** No private keys, no
transaction building, no signing, no decryption — it *cannot*. Keys, construction,
and every secret live client-side ([pydoge](https://github.com/ProfDoeg/pydoge)
+ cinv). A network-exposed daemon with no keys is the only safe daemon.

It reads only the **universal envelope** (magic · version · type · tone); the
body is opaque bytes. What a quipu *means* stays in the client — one
implementation of the format, in Python, never in C++.

## What it adds

The single new subsystem is the **read-index**: a spent-index (outpoint →
spending txid) and an address-index, written in `ConnectBlock` and unwound on
reorg, behind `-quipuindex`. On top of it, three RPCs:

| RPC | returns |
|---|---|
| `quipuread <txid>` | `{header, body, tags}` — walk a quipu from its root |
| `quipuroots <address>` | the quipu roots an address paid into |
| `quipuscan <address>` | `quipuread` for every quipu at an address |

`header` is the parsed universal envelope; `body` is the assembled strand bytes
(opaque); `tags` is the chain-state of the root's tag outputs — the edition /
correction thread, the one thing only the chain knows.

Everything else is stock Dogecoin Core. No format in C++, no transaction
building, no wallet keys: the diff is a few hundred lines, shaped to merge
upstream one day. Payloads are opaque bytes; the node never decodes meaning.

## Run

Build as Dogecoin Core (see [`doc/`](doc/)). Then populate the index once:

```
dogecoind -quipuindex -txindex -reindex-chainstate
dogecoin-cli quipuread <root-txid>
```

`-quipuindex` requires `-txindex` (the read walk fetches knot transactions).
Changing the flag requires `-reindex-chainstate`; after that it is read on
startup. The index is steady-state fast — no rescans, no per-knot round-trips.

## License

MIT, as Dogecoin Core. Portions © The Bitcoin Core and Dogecoin Core developers.
See [`COPYING`](COPYING).
