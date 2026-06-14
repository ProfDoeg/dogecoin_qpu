// Copyright (c) 2026 The Colegio Invisible / dogecoin_qpu developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// quipu read RPC — walk multi-strand OP_RETURN inscriptions ("quipu") using the
// keyless read-index (spentindex). Returns {header, body, tags}: the universal
// envelope, the opaque assembled body, and the chain-state of the root's tag
// outputs. The node decodes nothing type-specific; the client owns meaning.
// This is the C++ counterpart of colegio.reading.quipuread (the Python
// reference + differential oracle).

#include "rpc/server.h"
#include "rpc/protocol.h"
#include "validation.h"
#include "spentindex.h"
#include "chainparams.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"

#include <set>
#include <univalue.h>

static const unsigned char QUIPU_MAGIC0 = 0xc1;
static const unsigned char QUIPU_MAGIC1 = 0xdd;

// Extract an OP_RETURN pushdata payload from a scriptPubKey (mirrors
// colegio.reading.extract_op_return: bare <=75, then OP_PUSHDATA1/2/4).
static bool ExtractOpReturnPayload(const CScript& spk, std::vector<unsigned char>& out)
{
    if (spk.size() < 2 || spk[0] != OP_RETURN)
        return false;
    unsigned int n;
    size_t off;
    unsigned char b = spk[1];
    if (b <= 0x4b) { n = b; off = 2; }
    else if (b == 0x4c) { if (spk.size() < 3) return false; n = spk[2]; off = 3; }
    else if (b == 0x4d) { if (spk.size() < 4) return false; n = spk[2] | (spk[3] << 8); off = 4; }
    else if (b == 0x4e) { if (spk.size() < 6) return false;
        n = spk[2] | (spk[3] << 8) | (spk[4] << 16) | ((unsigned int)spk[5] << 24); off = 6; }
    else return false;
    if (spk.size() < off + n)
        return false;
    out.assign(spk.begin() + off, spk.begin() + off + n);
    return true;
}

// First OP_RETURN payload across a tx's outputs (true if any).
static bool TxOpReturn(const CTransaction& tx, std::vector<unsigned char>& out)
{
    for (unsigned int k = 0; k < tx.vout.size(); k++)
        if (ExtractOpReturnPayload(tx.vout[k].scriptPubKey, out))
            return true;
    return false;
}

// Walk one strand from (txid:vout): follow the chain of self-spending knots via
// the spent index, concatenating each knot's OP_RETURN payload (hex).
static std::string ReadStrand(const uint256& startTxid, int startVout,
                              const Consensus::Params& consensus)
{
    std::string result;
    uint256 cur = startTxid;
    int vout = startVout;
    std::set<uint256> seen;
    while (true) {
        CSpentIndexKey key(cur, vout);
        CSpentIndexValue value;
        if (!GetSpentIndex(key, value))
            break;                              // unspent → strand end
        if (seen.count(value.txid))
            break;                              // loop guard (malformed chain)
        seen.insert(value.txid);
        CTransactionRef spender;
        uint256 hashBlock;
        if (!GetTransaction(value.txid, spender, consensus, hashBlock, true))
            break;
        std::vector<unsigned char> payload;
        if (!TxOpReturn(*spender, payload))
            break;                              // knot without OP_RETURN → end
        result += HexStr(payload);
        cur = value.txid;
        vout = 0;                               // next knot spends this one's vout 0
    }
    return result;
}

// Parse the universal quipu envelope (magic/version/type/tone) + raw header hex.
// Type-agnostic by design: title/fields are type-specific and stay client-side.
static UniValue ParseEnvelope(const std::string& headerHex)
{
    std::vector<unsigned char> b = ParseHex(headerHex);
    if (b.size() < 6 || b[0] != QUIPU_MAGIC0 || b[1] != QUIPU_MAGIC1)
        throw JSONRPCError(RPC_MISC_ERROR,
            "not a quipu (c1dd magic missing from the header strand)");
    UniValue env(UniValue::VOBJ);
    env.pushKV("magic", HexStr(b.begin(), b.begin() + 2));
    env.pushKV("version", (int)((b[2] << 8) | b[3]));
    env.pushKV("type", (int)b[4]);
    env.pushKV("tone", (int)b[5]);
    env.pushKV("raw", headerHex);
    return env;
}

// Classify the root's outputs into tags (intact / SPENT), mirroring
// colegio.tags.classify_root_outputs filtered to kind == "tag". A strand output
// (its spender carries an OP_RETURN) is omitted; a tag is unspent (intact) or
// spent by a non-OP_RETURN tx (an event).
static UniValue ClassifyRootTags(const uint256& root, const Consensus::Params& consensus)
{
    UniValue tags(UniValue::VARR);
    CTransactionRef rootTx;
    uint256 hashBlock;
    if (!GetTransaction(root, rootTx, consensus, hashBlock, true))
        return tags;
    for (unsigned int i = 0; i < rootTx->vout.size(); i++) {
        CSpentIndexKey key(root, i);
        CSpentIndexValue value;
        bool spent = GetSpentIndex(key, value);
        std::string state;
        std::string spentBy;
        if (!spent) {
            state = "intact";
        } else {
            CTransactionRef spender;
            uint256 hb;
            std::vector<unsigned char> payload;
            bool isStrand = GetTransaction(value.txid, spender, consensus, hb, true)
                            && TxOpReturn(*spender, payload);
            if (isStrand)
                continue;                       // a strand, not a tag
            state = "SPENT";
            spentBy = value.txid.GetHex();
        }
        UniValue t(UniValue::VOBJ);
        t.pushKV("vout", (int)i);
        t.pushKV("value", (int64_t)rootTx->vout[i].nValue);
        t.pushKV("script", HexStr(rootTx->vout[i].scriptPubKey));
        t.pushKV("state", state);
        t.pushKV("spent_by", spentBy);
        tags.push_back(t);
    }
    return tags;
}

UniValue quipuread(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "quipuread \"txid\"\n"
            "\nWalk a quipu from its root transaction and return its contents.\n"
            "Requires -quipuindex (and -txindex).\n"
            "\nArguments:\n"
            "1. \"txid\"   (string, required) the quipu root txid\n"
            "\nResult:\n"
            "{\n"
            "  \"header\": {\"magic\",\"version\",\"type\",\"tone\",\"raw\"},\n"
            "  \"body\": \"hex\",   (assembled body strands, opaque to the node)\n"
            "  \"tags\": [{\"vout\",\"value\",\"script\",\"state\",\"spent_by\"}]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("quipuread", "\"<txid>\"")
            + HelpExampleRpc("quipuread", "\"<txid>\""));

    if (!fSpentIndex)
        throw JSONRPCError(RPC_MISC_ERROR,
            "quipu read-index not enabled. Run with -quipuindex and -txindex, then -reindex-chainstate.");

    uint256 root = ParseHashV(request.params[0], "txid");
    const Consensus::Params& consensus = Params().GetConsensus(0);

    LOCK(cs_main);

    std::string headerHex = ReadStrand(root, 0, consensus);
    std::string bodyHex;
    for (int v = 1; ; v++) {
        std::string strand = ReadStrand(root, v, consensus);
        if (strand.empty())
            break;
        bodyHex += strand;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("header", ParseEnvelope(headerHex));
    result.pushKV("body", bodyHex);
    result.pushKV("tags", ClassifyRootTags(root, consensus));
    return result;
}

static const CRPCCommand commands[] =
{ //  category      name          actor (function)   okSafeMode  argNames
    { "quipu",      "quipuread",  &quipuread,        true,       {"txid"} },
};

void RegisterQuipuRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
