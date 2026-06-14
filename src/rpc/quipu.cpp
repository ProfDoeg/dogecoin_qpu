// Copyright (c) 2026 The Colegio Invisible / dogecoin_qpu developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// quipu read RPC — walk multi-strand OP_RETURN inscriptions ("quipu") using the
// keyless read-index (spentindex + addressindex). The C++ counterpart of
// colegio.reading (the Python reference + differential oracle):
//   quipuread  <txid>    -> {header, body, tags}
//   quipuroots <address> -> [root txid, ...]
//   quipuscan  <address> -> [{root, header, body, tags}, ...]
// The node decodes nothing type-specific; the client owns meaning.

#include "rpc/server.h"
#include "rpc/protocol.h"
#include "validation.h"
#include "spentindex.h"
#include "base58.h"
#include "chainparams.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
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
// colegio.tags.classify_root_outputs filtered to kind == "tag".
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

// Assemble {header, body, tags} for a quipu root (the shared read core).
static UniValue ReadQuipuObj(const uint256& root, const Consensus::Params& consensus)
{
    std::string headerHex = ReadStrand(root, 0, consensus);
    std::string bodyHex;
    for (int v = 1; ; v++) {
        std::string strand = ReadStrand(root, v, consensus);
        if (strand.empty())
            break;
        bodyHex += strand;
    }
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("header", ParseEnvelope(headerHex));
    obj.pushKV("body", bodyHex);
    obj.pushKV("tags", ClassifyRootTags(root, consensus));
    return obj;
}

// Decode an address to its index key (uint160 hash + type 1=P2PKH, 2=P2SH).
static bool DecodeAddressToIndexKey(const std::string& addr, uint160& hashBytes, int& type)
{
    CBitcoinAddress address(addr);
    if (!address.IsValid())
        return false;
    CTxDestination dest = address.Get();
    if (dest.type() == typeid(CKeyID)) {
        hashBytes = boost::get<CKeyID>(dest);
        type = 1;
        return true;
    }
    if (dest.type() == typeid(CScriptID)) {
        hashBytes = boost::get<CScriptID>(dest);
        type = 2;
        return true;
    }
    return false;
}

// A quipu root carries no OP_RETURN of its own, and the spend of its output 0
// is the cabeza's first knot (its OP_RETURN starts with the c1dd magic). Mirrors
// colegio.reading.identify_quipus.
static bool IsQuipuRoot(const uint256& txid, const Consensus::Params& consensus)
{
    CTransactionRef tx;
    uint256 hb;
    if (!GetTransaction(txid, tx, consensus, hb, true))
        return false;
    std::vector<unsigned char> own;
    if (TxOpReturn(*tx, own))
        return false;                           // a root has no OP_RETURN of its own
    CSpentIndexKey key(txid, 0);
    CSpentIndexValue value;
    if (!GetSpentIndex(key, value))
        return false;                           // output 0 unspent → not inscribed
    CTransactionRef spender;
    uint256 hb2;
    if (!GetTransaction(value.txid, spender, consensus, hb2, true))
        return false;
    std::vector<unsigned char> payload;
    if (!TxOpReturn(*spender, payload))
        return false;
    return payload.size() >= 2 && payload[0] == QUIPU_MAGIC0 && payload[1] == QUIPU_MAGIC1;
}

// Quipu roots whose outputs pay `address` (via the address index). Returns a set
// to dedupe (a root may pay the address in more than one output).
static std::set<uint256> QuipuRootsForAddress(const std::string& addr,
                                              const Consensus::Params& consensus)
{
    uint160 hashBytes;
    int type;
    if (!DecodeAddressToIndexKey(addr, hashBytes, type))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    std::vector<std::pair<CAddressIndexKey, CAmount> > entries;
    if (!GetAddressIndex(hashBytes, type, entries))
        throw JSONRPCError(RPC_MISC_ERROR, "No information available for address");
    std::set<uint256> candidates;
    for (unsigned int i = 0; i < entries.size(); i++)
        if (!entries[i].first.spending)         // received outputs → candidate roots
            candidates.insert(entries[i].first.txhash);
    std::set<uint256> roots;
    for (std::set<uint256>::const_iterator it = candidates.begin(); it != candidates.end(); ++it)
        if (IsQuipuRoot(*it, consensus))
            roots.insert(*it);
    return roots;
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
    return ReadQuipuObj(root, consensus);
}

UniValue quipuroots(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "quipuroots \"address\"\n"
            "\nList the quipu root txids whose outputs pay the given address.\n"
            "Requires -quipuindex (and -txindex).\n"
            "\nArguments:\n"
            "1. \"address\"   (string, required) the address to scan\n"
            "\nResult:\n"
            "[ \"txid\", ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("quipuroots", "\"<address>\"")
            + HelpExampleRpc("quipuroots", "\"<address>\""));

    if (!fAddressIndex)
        throw JSONRPCError(RPC_MISC_ERROR,
            "quipu read-index not enabled. Run with -quipuindex and -txindex, then -reindex-chainstate.");

    const Consensus::Params& consensus = Params().GetConsensus(0);
    LOCK(cs_main);
    std::set<uint256> roots = QuipuRootsForAddress(request.params[0].get_str(), consensus);
    UniValue result(UniValue::VARR);
    for (std::set<uint256>::const_iterator it = roots.begin(); it != roots.end(); ++it)
        result.push_back(it->GetHex());
    return result;
}

UniValue quipuscan(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "quipuscan \"address\"\n"
            "\nRead every quipu whose outputs pay the given address.\n"
            "Requires -quipuindex (and -txindex).\n"
            "\nArguments:\n"
            "1. \"address\"   (string, required) the address to scan\n"
            "\nResult:\n"
            "[ {\"root\", \"header\", \"body\", \"tags\"}, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("quipuscan", "\"<address>\"")
            + HelpExampleRpc("quipuscan", "\"<address>\""));

    if (!fAddressIndex)
        throw JSONRPCError(RPC_MISC_ERROR,
            "quipu read-index not enabled. Run with -quipuindex and -txindex, then -reindex-chainstate.");

    const Consensus::Params& consensus = Params().GetConsensus(0);
    LOCK(cs_main);
    std::set<uint256> roots = QuipuRootsForAddress(request.params[0].get_str(), consensus);
    UniValue result(UniValue::VARR);
    for (std::set<uint256>::const_iterator it = roots.begin(); it != roots.end(); ++it) {
        UniValue q = ReadQuipuObj(*it, consensus);
        q.pushKV("root", it->GetHex());
        result.push_back(q);
    }
    return result;
}

static const CRPCCommand commands[] =
{ //  category      name           actor (function)   okSafeMode  argNames
    { "quipu",      "quipuread",   &quipuread,        true,       {"txid"} },
    { "quipu",      "quipuroots",  &quipuroots,       true,       {"address"} },
    { "quipu",      "quipuscan",   &quipuscan,        true,       {"address"} },
};

void RegisterQuipuRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
