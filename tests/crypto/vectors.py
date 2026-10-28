"""Known-answer test vectors.

Every ``*_BYTES`` value is a preimage written by hand from the specification in docs/DESIGN.md,
not produced by project code. Every digest was computed over those exact bytes with two external
tools, GNU coreutils ``sha256sum`` 8.32 and PowerShell 5.1 ``Get-FileHash -Algorithm SHA256``,
which agreed on all 22 vectors (2026-10-28). See docs/DEVELOPMENT.md, "Known-answer vectors".

Strings use escapes for non-ASCII characters so the exact code points are visible.
"""

from aip.crypto.canonical import JsonValue


def salt(index: int) -> bytes:
    """Fixed test salt: 32 bytes all equal to ``index``."""
    return bytes([index]) * 32


def salt_hex(index: int) -> bytes:
    return salt(index).hex().encode()


GENESIS_BYTES = b"0" * 64

# --- Canonical JSON: (name, input value, expected canonical bytes, sha256 of those bytes) ---
CANONICAL_VECTORS: list[tuple[str, JsonValue, bytes, str]] = [
    (
        "K_ORDER",
        {"b": 1, "a": [True, False, None], "c": "x"},
        b'{"a":[true,false,null],"b":1,"c":"x"}',
        "210bd8e5501c622e789c4b9e6cd70edbfbe598f4725066bac3c1ffe0176ff0e3",
    ),
    (
        "K_ESCAPES",
        {"s": '\u0001\b\f\n\r\t"\\/\u001f'},
        rb'{"s":"\u0001\b\f\n\r\t\"\\/\u001f"}',
        "1de88f90a7ddd5569513ae99224ed898095222e5fd7bfde896d18c53fb24d9dd",
    ),
    (
        "K_UNICODE_RAW",
        {"k": "caf\u00e9 \u20ac \u007f \u2028"},
        b'{"k":"caf\xc3\xa9 \xe2\x82\xac \x7f \xe2\x80\xa8"}',
        "cfac0e68b27544c1ad83509e76213c7bfd11472c6304a02f150e63526030ad44",
    ),
    (
        # UTF-16 code-unit order puts U+1F600 (D83D DE00) before U+E000; code-point order would not.
        "K_UTF16_ORDER",
        {"\ue000": 1, "\U0001f600": 2},
        b'{"\xf0\x9f\x98\x80":2,"\xee\x80\x80":1}',
        "28c95d1bbb2209223307e62f489020e8f9e0cfa16adf2daf6d88127a1e8dd22a",
    ),
    (
        "K_INTEGERS",
        {"n": [0, -1, 9007199254740991, -9007199254740991]},
        b'{"n":[0,-1,9007199254740991,-9007199254740991]}',
        "9865c628036ff2e59e127da0efe0c5f7bb4655b981608640ec0528f4662ddd4e",
    ),
    (
        "K_EMPTY",
        {"a": {}, "b": [], "c": [{}], "d": {"e": []}},
        b'{"a":{},"b":[],"c":[{}],"d":{"e":[]}}',
        "f6134eb6134f4e6ca1f2c46d313aa3d20ed458f1ed9ad6dce4306a0015dd2a42",
    ),
    (
        # RFC 8785 section 3.2.2 sample without its "numbers" member (floats are not accepted here).
        # Expected bytes are the RFC section 3.2.4 hex dump with the numbers member removed.
        "RFC8785_STRING_LITERALS",
        {"string": '\u20ac$\u000f\nA\'B"\\\\"/', "literals": [None, True, False]},
        bytes.fromhex("7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c")
        + bytes.fromhex("22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"),
        "834b0ae0dd68944f19836aa49d608aa4975f03998f927466f8b648d5f927ecee",
    ),
    (
        # RFC 8785 section 3.2.3 sorting sample without U+FB33, which is not NFC-normalized.
        "RFC8785_SORT_WITHOUT_FB33",
        {
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "1": "One",
            "\U0001f600": "Emoji: Grinning Face",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis",
        },
        b'{"\\r":"Carriage Return","1":"One","\xc2\x80":"Control",'
        b'"\xc3\xb6":"Latin Small Letter O With Diaeresis","\xe2\x82\xac":"Euro Sign",'
        b'"\xf0\x9f\x98\x80":"Emoji: Grinning Face"}',
        "9044f6b34e92c276de1aebc14fb1fcffa77bee065f936a90baa026a76d68d43f",
    ),
]

RFC8785_SORT_SAMPLE_FULL: dict[str, JsonValue] = {
    "\u20ac": "Euro Sign",
    "\r": "Carriage Return",
    "\ufb33": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "\U0001f600": "Emoji: Grinning Face",
    "\u0080": "Control",
    "\u00f6": "Latin Small Letter O With Diaeresis",
}
RFC8785_SORT_EXPECTED_ORDER = [
    "Carriage Return",
    "One",
    "Control",
    "Latin Small Letter O With Diaeresis",
    "Euro Sign",
    "Emoji: Grinning Face",
    "Hebrew Letter Dalet With Dagesh",
]

# --- Leaf commitments for PAYLOAD with salts 0..5 assigned in canonical path order ---
PAYLOAD: dict[str, JsonValue] = {
    "account": {"number": "900123456", "type": "BROKERAGE"},
    "flags": [True, None],
    "note": "caf\u00e9",
    "empty": {},
}

# (typed path, value, salt index, hand-written preimage, sha256)
LEAF_VECTORS: list[tuple[tuple[str | int, ...], JsonValue, int, bytes, str]] = [
    (
        ("account", "number"),
        "900123456",
        0,
        b'["aip-leaf-v1",["account","number"],"' + salt_hex(0) + b'","900123456"]',
        "a3e9c3c0753316e44ff426c0cfca82c6f3458b05ee0a8089430dfc58a43facf5",
    ),
    (
        ("account", "type"),
        "BROKERAGE",
        1,
        b'["aip-leaf-v1",["account","type"],"' + salt_hex(1) + b'","BROKERAGE"]',
        "54feca64b779cde95a5812c18283fc1b4deaad799224357a1ec3abd9fee33e77",
    ),
    (
        ("empty",),
        {},
        2,
        b'["aip-leaf-v1",["empty"],"' + salt_hex(2) + b'",{}]',
        "0a8203a8763ce6cf25d6637690e327aa27710457458db14672ee1f16d08d2532",
    ),
    (
        ("flags", 0),
        True,
        3,
        b'["aip-leaf-v1",["flags",0],"' + salt_hex(3) + b'",true]',
        "7e4ba8d02a93ebc0e75813b0f4834a8f74dfe3afd1957bdd1bfbd117b36f444e",
    ),
    (
        ("flags", 1),
        None,
        4,
        b'["aip-leaf-v1",["flags",1],"' + salt_hex(4) + b'",null]',
        "c5566275fb8be5588c13aad8cfdb16316ac9d6dd59e4f25eb308966318b6e497",
    ),
    (
        ("note",),
        "caf\u00e9",
        5,
        b'["aip-leaf-v1",["note"],"' + salt_hex(5) + b'","caf\xc3\xa9"]',
        "ba063de206d82f77591f3784ff6e1f2cf062de2bc54cd264162804f9b66ff8c2",
    ),
]

PAYLOAD_ROOT_BYTES = (
    b'{"leaves":[[["account","number"],"'
    b'a3e9c3c0753316e44ff426c0cfca82c6f3458b05ee0a8089430dfc58a43facf5"],'
    b'[["account","type"],"54feca64b779cde95a5812c18283fc1b4deaad799224357a1ec3abd9fee33e77"],'
    b'[["empty"],"0a8203a8763ce6cf25d6637690e327aa27710457458db14672ee1f16d08d2532"],'
    b'[["flags",0],"7e4ba8d02a93ebc0e75813b0f4834a8f74dfe3afd1957bdd1bfbd117b36f444e"],'
    b'[["flags",1],"c5566275fb8be5588c13aad8cfdb16316ac9d6dd59e4f25eb308966318b6e497"],'
    b'[["note"],"ba063de206d82f77591f3784ff6e1f2cf062de2bc54cd264162804f9b66ff8c2"]],'
    b'"t":"aip.payload","v":1}'
)
PAYLOAD_ROOT = "92017f911f18334504f6977c7490c8162407ecdac97f7a79c549a586b48c1c6a"

# --- Typed-path regression: {"a": ["x"]} versus {"a": {"0": "x"}}, both with salt 0 ---
TYPED_ARRAY_LEAF_BYTES = b'["aip-leaf-v1",["a",0],"' + salt_hex(0) + b'","x"]'
TYPED_ARRAY_LEAF = "0283a03faad3a91160ef9f473dda2fc333757ee5bfb33d9911bb33d546bf2edd"
TYPED_ARRAY_ROOT = "245e1f79c3d3658a1ed9cdc2ec2d40386df258e7278c72ed365f432f44c95022"
TYPED_OBJECT_LEAF_BYTES = b'["aip-leaf-v1",["a","0"],"' + salt_hex(0) + b'","x"]'
TYPED_OBJECT_LEAF = "7e408c00e12738be2a630d2a154b7a52f91ea3152c4413c55ad0f167bbc778fe"
TYPED_OBJECT_ROOT = "b7d0a802f1d5add7a2b91ea87b91048cad727e3a9f492c47ed73648a55f9e744"

# --- Content hash over the envelope below and PAYLOAD_ROOT ---
ENVELOPE = {
    "event_type": "RECORD_UPDATED",
    "actor_id": "user-0042",
    "resource_type": "CLIENT_ACCOUNT",
    "resource_id": "acct-0001",
    "timestamp": "2026-10-28T12:00:00.000000Z",
}
CONTENT_BYTES = (
    b'{"actorId":"user-0042","eventType":"RECORD_UPDATED","payloadRoot":"'
    b'92017f911f18334504f6977c7490c8162407ecdac97f7a79c549a586b48c1c6a",'
    b'"resourceId":"acct-0001","resourceType":"CLIENT_ACCOUNT","t":"aip.content",'
    b'"timestamp":"2026-10-28T12:00:00.000000Z","v":1}'
)
CONTENT_HASH = "bb86bfeee662a1edefd8d34c6232064c0d96b0a75628f6498e12e7f986364ec6"

# --- Record hashes: seq 1 links to GENESIS, seq 2 links to seq 1 ---
RECORD_1_AT = "2026-10-28T12:00:01.000000Z"
RECORD_1_BYTES = (
    b'{"contentHash":"bb86bfeee662a1edefd8d34c6232064c0d96b0a75628f6498e12e7f986364ec6",'
    b'"prevHash":"' + GENESIS_BYTES + b'",'
    b'"recordedAt":"2026-10-28T12:00:01.000000Z","seq":1,"t":"aip.record","v":1}'
)
RECORD_1_HASH = "498bc8362e44699267cf3a59e566ccfd64597d6bf792f88c2f2cb34012732140"
RECORD_2_AT = "2026-10-28T12:00:02.000000Z"
RECORD_2_BYTES = (
    b'{"contentHash":"bb86bfeee662a1edefd8d34c6232064c0d96b0a75628f6498e12e7f986364ec6",'
    b'"prevHash":"498bc8362e44699267cf3a59e566ccfd64597d6bf792f88c2f2cb34012732140",'
    b'"recordedAt":"2026-10-28T12:00:02.000000Z","seq":2,"t":"aip.record","v":1}'
)
RECORD_2_HASH = "e41c251cc1cc63171649ba6db4301b594c66f174e8ca9947253a07bbf04738f5"
