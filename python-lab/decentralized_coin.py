"""Decentralized UTXO Coin using Lamport One-Time Signatures + optional OTP memos.

Architecture:
- No central Mint: independent peer Nodes verify every block, PoW hash, UTXO,
  and Lamport one-time signature from scratch.
- UTXO model: each unspent output is locked to a fresh one-time Lamport address.
  Spending a UTXO consumes it completely and sends any change to a BRAND-NEW
  one-time address so private keys are never reused.
- On-chain privacy: senders and recipients who share a One-Time Pad can attach
  an OTP-encrypted memo right inside a public transaction output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from lamport_ots import LamportKeyPair, verify_lamport_signature
from otp_crypto import otp_xor

BLOCK_REWARD = 50


class ConsensusError(Exception):
    """Raised when a transaction or block violates decentralized consensus rules."""


@dataclass(frozen=True)
class TxOutput:
    amount: int
    address: str
    otp_memo_hex: str = ""  # Optional OTP-encrypted memo (readable only with shared pad)

    def to_dict(self) -> dict:
        return {
            "amount": self.amount,
            "address": self.address,
            "otp_memo_hex": self.otp_memo_hex,
        }


@dataclass(frozen=True)
class TxInput:
    prev_tx_id: str
    output_index: int
    public_key: list[tuple[bytes, bytes]]
    signature: list[bytes]

    @property
    def outpoint(self) -> tuple[str, int]:
        return (self.prev_tx_id, self.output_index)


@dataclass(frozen=True)
class Transaction:
    inputs: list[TxInput]
    outputs: list[TxOutput]
    is_coinbase: bool = False
    coinbase_height: int = 0

    def signing_payload(self) -> bytes:
        """Canonical bytes signed by every input's Lamport one-time key."""
        body = {
            "inputs": [
                {"prev_tx_id": inp.prev_tx_id, "output_index": inp.output_index}
                for inp in self.inputs
            ],
            "outputs": [out.to_dict() for out in self.outputs],
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def tx_id(self) -> str:
        """Unique SHA-256 identifier of this transaction."""
        h = hashlib.sha256()
        h.update(b"coinbase:" if self.is_coinbase else b"spend:")
        h.update(str(self.coinbase_height).encode("utf-8"))
        h.update(self.signing_payload())
        for inp in self.inputs:
            for sig_part in inp.signature:
                h.update(sig_part)
        return h.hexdigest()


@dataclass(frozen=True)
class Block:
    index: int
    prev_hash: str
    transactions: list[Transaction]
    difficulty: int
    nonce: int
    block_hash: str

    @staticmethod
    def compute_hash(
        index: int,
        prev_hash: str,
        tx_ids: list[str],
        difficulty: int,
        nonce: int,
    ) -> str:
        header = json.dumps(
            {
                "index": index,
                "prev_hash": prev_hash,
                "tx_ids": tx_ids,
                "difficulty": difficulty,
                "nonce": nonce,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(header).hexdigest()


class UTXOWallet:
    """Decentralized wallet managing single-use Lamport keypairs."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._keys: dict[str, LamportKeyPair] = {}

    def new_address(self) -> str:
        """Generate and store a fresh one-time Lamport address."""
        kp = LamportKeyPair.generate()
        self._keys[kp.address] = kp
        return kp.address

    def get_keypair(self, address: str) -> LamportKeyPair:
        return self._keys[address]

    def balance(self, node: "Node") -> int:
        return sum(
            out.amount
            for out in node.utxo_set.values()
            if out.address in self._keys
        )

    def decrypt_memo(self, output: TxOutput, shared_otp: bytes) -> str:
        """Decrypt an on-chain OTP-encrypted memo using a pre-shared one-time pad."""
        ciphertext = bytes.fromhex(output.otp_memo_hex)
        return otp_xor(ciphertext, shared_otp).decode("utf-8")

    def create_transaction(
        self,
        node: "Node",
        recipient_address: str,
        amount: int,
        *,
        memo: str = "",
        shared_otp: bytes | None = None,
    ) -> Transaction:
        """Spend owned UTXOs, signing each with its one-time Lamport key."""
        if amount <= 0:
            raise ValueError("Transfer amount must be positive.")

        # Select owned UTXOs from the node's current UTXO set.
        selected: list[tuple[tuple[str, int], TxOutput]] = []
        total_in = 0
        for outpoint, utxo in node.utxo_set.items():
            if utxo.address in self._keys and not self._keys[utxo.address].used:
                selected.append((outpoint, utxo))
                total_in += utxo.amount
                if total_in >= amount:
                    break

        if total_in < amount:
            raise ValueError(
                f"Wallet '{self.name}' has {total_in} spendable coins, needs {amount}."
            )

        otp_memo_hex = ""
        if memo:
            if shared_otp is None:
                raise ValueError("A shared one-time pad is required to encrypt a memo.")
            otp_memo_hex = otp_xor(memo.encode("utf-8"), shared_otp).hex()

        outputs = [
            TxOutput(
                amount=amount,
                address=recipient_address,
                otp_memo_hex=otp_memo_hex,
            )
        ]

        # CRITICAL for one-time signatures: send change to a BRAND-NEW address!
        change = total_in - amount
        if change > 0:
            change_addr = self.new_address()
            outputs.append(TxOutput(amount=change, address=change_addr))

        # Build unsigned skeleton to compute canonical signing payload.
        unsigned = Transaction(
            inputs=[
                TxInput(
                    prev_tx_id=tx_id,
                    output_index=idx,
                    public_key=[],
                    signature=[],
                )
                for (tx_id, idx), _ in selected
            ],
            outputs=outputs,
        )
        payload = unsigned.signing_payload()

        signed_inputs: list[TxInput] = []
        for (tx_id, idx), utxo in selected:
            kp = self._keys[utxo.address]
            sig = kp.sign(payload)
            signed_inputs.append(
                TxInput(
                    prev_tx_id=tx_id,
                    output_index=idx,
                    public_key=kp.public_key,
                    signature=sig,
                )
            )

        return Transaction(inputs=signed_inputs, outputs=outputs)


class Node:
    """An independent decentralized peer maintaining chain state & UTXO set."""

    def __init__(self, node_id: str, difficulty: int = 2) -> None:
        self.node_id = node_id
        self.difficulty = difficulty
        self.chain: list[Block] = []
        self.utxo_set: dict[tuple[str, int], TxOutput] = {}
        self.spent_addresses: set[str] = set()
        self.mempool: list[Transaction] = []
        self._init_genesis()

    def _init_genesis(self) -> None:
        genesis = Block(
            index=0,
            prev_hash="0" * 64,
            transactions=[],
            difficulty=self.difficulty,
            nonce=0,
            block_hash=Block.compute_hash(0, "0" * 64, [], self.difficulty, 0),
        )
        self.chain = [genesis]

    @property
    def tip(self) -> Block:
        return self.chain[-1]

    @staticmethod
    def _validate_tx_against_state(
        tx: Transaction,
        utxos: dict[tuple[str, int], TxOutput],
        spent_addrs: set[str],
    ) -> tuple[dict[tuple[str, int], TxOutput], set[str]]:
        """Validate a non-coinbase transaction and return updated (utxos, spent_addrs)."""
        if tx.is_coinbase:
            raise ConsensusError("Unexpected coinbase transaction.")
        if not tx.inputs or not tx.outputs:
            raise ConsensusError("Transaction must have at least one input and output.")

        seen_outpoints: set[tuple[str, int]] = set()
        payload = tx.signing_payload()
        total_in = 0
        newly_spent_addrs: set[str] = set()

        for inp in tx.inputs:
            if inp.outpoint in seen_outpoints:
                raise ConsensusError(f"Duplicate input outpoint {inp.outpoint}.")
            if inp.outpoint not in utxos:
                raise ConsensusError(
                    f"Double-spend or missing UTXO: {inp.prev_tx_id[:10]}...:{inp.output_index}"
                )
            utxo = utxos[inp.outpoint]
            if not verify_lamport_signature(
                payload, utxo.address, inp.public_key, inp.signature
            ):
                raise ConsensusError(
                    f"Invalid Lamport one-time signature for address {utxo.address[:12]}..."
                )
            seen_outpoints.add(inp.outpoint)
            newly_spent_addrs.add(utxo.address)
            total_in += utxo.amount

        total_out = 0
        for out in tx.outputs:
            if not isinstance(out.amount, int) or isinstance(out.amount, bool) or out.amount <= 0:
                raise ConsensusError("Output amount must be a positive integer.")
            if out.address in spent_addrs or out.address in newly_spent_addrs:
                raise ConsensusError(
                    f"Address reuse forbidden for one-time Lamport address {out.address[:12]}..."
                )
            total_out += out.amount

        if total_out > total_in:
            raise ConsensusError(
                f"Outputs ({total_out}) exceed inputs ({total_in})."
            )

        new_utxos = {k: v for k, v in utxos.items() if k not in seen_outpoints}
        tid = tx.tx_id
        for idx, out in enumerate(tx.outputs):
            new_utxos[(tid, idx)] = out
        new_spent = spent_addrs | newly_spent_addrs
        return new_utxos, new_spent

    def submit_transaction(self, tx: Transaction) -> str:
        """Validate a transaction against current UTXO + mempool and queue it."""
        # Replay pending mempool transactions to prevent mempool double-spends.
        temp_utxos = dict(self.utxo_set)
        temp_spent = set(self.spent_addresses)
        for pending in self.mempool:
            temp_utxos, temp_spent = self._validate_tx_against_state(
                pending, temp_utxos, temp_spent
            )
        self._validate_tx_against_state(tx, temp_utxos, temp_spent)
        self.mempool.append(tx)
        return tx.tx_id

    def mine_block(self, miner_address: str) -> Block:
        """Mine a new PoW block containing the coinbase reward + pending mempool txs."""
        if miner_address in self.spent_addresses:
            raise ConsensusError("Miner address was already spent; use a fresh one-time address.")

        next_index = self.tip.index + 1
        coinbase = Transaction(
            inputs=[],
            outputs=[TxOutput(amount=BLOCK_REWARD, address=miner_address)],
            is_coinbase=True,
            coinbase_height=next_index,
        )
        txs = [coinbase] + list(self.mempool)
        tx_ids = [t.tx_id for t in txs]
        target = "0" * self.difficulty

        nonce = 0
        while True:
            bhash = Block.compute_hash(
                next_index, self.tip.block_hash, tx_ids, self.difficulty, nonce
            )
            if bhash.startswith(target):
                break
            nonce += 1

        block = Block(
            index=next_index,
            prev_hash=self.tip.block_hash,
            transactions=txs,
            difficulty=self.difficulty,
            nonce=nonce,
            block_hash=bhash,
        )
        self.receive_block(block)
        return block

    def receive_block(self, block: Block) -> None:
        """Independently verify a block and apply it to local state."""
        if block.index != self.tip.index + 1:
            raise ConsensusError("Block index does not extend current chain tip.")
        if block.prev_hash != self.tip.block_hash:
            raise ConsensusError("Block prev_hash does not match chain tip.")
        if block.difficulty != self.difficulty:
            raise ConsensusError("Block difficulty mismatch.")

        tx_ids = [t.tx_id for t in block.transactions]
        expected_hash = Block.compute_hash(
            block.index, block.prev_hash, tx_ids, block.difficulty, block.nonce
        )
        if block.block_hash != expected_hash or not block.block_hash.startswith(
            "0" * self.difficulty
        ):
            raise ConsensusError("Invalid Proof-of-Work hash.")

        if not block.transactions or not block.transactions[0].is_coinbase:
            raise ConsensusError("First transaction in block must be coinbase.")

        cb = block.transactions[0]
        if (
            len(cb.inputs) != 0
            or len(cb.outputs) != 1
            or cb.outputs[0].amount != BLOCK_REWARD
        ):
            raise ConsensusError("Invalid coinbase transaction.")

        temp_utxos = dict(self.utxo_set)
        temp_spent = set(self.spent_addresses)

        cb_out = cb.outputs[0]
        if cb_out.address in temp_spent:
            raise ConsensusError("Coinbase cannot pay to an already-spent one-time address.")
        temp_utxos[(cb.tx_id, 0)] = cb_out

        for tx in block.transactions[1:]:
            temp_utxos, temp_spent = self._validate_tx_against_state(
                tx, temp_utxos, temp_spent
            )

        self.chain.append(block)
        self.utxo_set = temp_utxos
        self.spent_addresses = temp_spent
        mined_ids = set(tx_ids)
        self.mempool = [t for t in self.mempool if t.tx_id not in mined_ids]

    def sync_from(self, peer: "Node") -> bool:
        """Adopt a peer's chain if it is strictly longer and 100% independently valid."""
        if len(peer.chain) <= len(self.chain):
            return False

        scratch = Node(node_id=f"{self.node_id}-verify", difficulty=self.difficulty)
        if peer.chain[0].block_hash != scratch.chain[0].block_hash:
            raise ConsensusError("Genesis block mismatch.")
        for block in peer.chain[1:]:
            scratch.receive_block(block)

        self.chain = scratch.chain
        self.utxo_set = scratch.utxo_set
        self.spent_addresses = scratch.spent_addresses
        self.mempool = []
        return True
