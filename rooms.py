import time
import hmac
import secrets
import asyncio
import hashlib
import logging
from typing import Dict, Optional, Awaitable, Callable
from fastapi import WebSocket

logger = logging.getLogger("QR-CipherChat.Rooms")

MAX_FAILED_ATTEMPTS = 3
MAX_ROOMS = 200
DEFAULT_TTL_MINUTES = 30
ALLOWED_TTL_MINUTES = (5, 15, 30, 60, 120)
RECONNECT_GRACE_SECONDS = 45      # How long a dropped peer may take to come back before the room burns
UNCLAIMED_TIMEOUT_SECONDS = 600   # A room nobody is connected to and that never paired dies after this

ROLES = ("creator", "recipient")


def _normalise_name(name: str) -> str:
    return " ".join((name or "").split()).casefold()


def _pin_digest(pin: str) -> bytes:
    return hashlib.sha256((pin or "").strip().encode()).digest()


class EphemeralRoom:
    def __init__(self, room_id: str, creator_alias: str, target_recipient: str,
                 secret_pin: str, ttl_minutes: int,
                 on_burn: Callable[[str, str], Awaitable[None]]):
        self.room_id = room_id
        self.token = secrets.token_hex(16)       # In the QR / link: proves you were sent the link
        self.host_key = secrets.token_hex(16)    # Only ever given to the creator's browser
        self.guest_key: Optional[str] = None     # Issued to the first device that unlocks as the recipient
        self.creator_alias = creator_alias.strip()
        self.target_recipient = target_recipient.strip()
        self._pin = _pin_digest(secret_pin) if secret_pin.strip() else None
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl_minutes * 60
        self.last_activity = self.created_at
        self.failed_attempts = 0
        self.is_destroyed = False
        self.paired_once = False
        self._on_burn = on_burn

        # Volatile RAM-only sockets: role -> {"ws", "alias", "conn_id"}
        self.connections: Dict[str, dict] = {}
        self._grace_tasks: Dict[str, asyncio.Task] = {}

    # ------------------------------------------------------------------ status
    @property
    def has_pin(self) -> bool:
        return self._pin is not None

    @property
    def status(self) -> str:
        if self.is_destroyed:
            return "destroyed"
        if len(self.connections) == 2:
            return "paired"
        return "waiting"

    @property
    def expires_in(self) -> int:
        return max(0, int(self.expires_at - time.time()))

    # ------------------------------------------------------------------ access control
    def check_token(self, token: str) -> bool:
        return hmac.compare_digest(self.token, token or "")

    def check_host_key(self, key: str) -> bool:
        return hmac.compare_digest(self.host_key, key or "")

    def check_guest_key(self, key: str) -> bool:
        return self.guest_key is not None and hmac.compare_digest(self.guest_key, key or "")

    def check_member_key(self, key: str) -> Optional[str]:
        if self.check_host_key(key):
            return "creator"
        if self.check_guest_key(key):
            return "recipient"
        return None

    def verify_recipient(self, claimed_name: str, pin: str, guest_key: str = "") -> tuple[bool, str]:
        """
        Only the designated recipient (X) may unlock. Anyone else holding the link (Y, Z)
        is rejected and counted towards the intruder lockout. Once X has unlocked on one
        device, the room is claimed and no other device can enter as X.
        """
        if self.is_destroyed:
            return False, "This room has been vaporized and no longer exists."

        # A returning recipient (page refresh / reconnect) proves itself with its key
        if guest_key and self.check_guest_key(guest_key):
            return True, self.guest_key

        name_ok = _normalise_name(claimed_name) == _normalise_name(self.target_recipient)
        pin_ok = self._pin is None or hmac.compare_digest(self._pin, _pin_digest(pin))

        if not (name_ok and pin_ok):
            self.failed_attempts += 1
            left = MAX_FAILED_ATTEMPTS - self.failed_attempts
            logger.warning(f"Rejected unlock on room {self.room_id} ({self.failed_attempts}/{MAX_FAILED_ATTEMPTS})")
            if left <= 0:
                return False, f"SECURITY PURGE: {MAX_FAILED_ATTEMPTS} unauthorized attempts. Room destroyed permanently."
            if not name_ok:
                return False, (f"ACCESS DENIED: this room is locked to one specific person and "
                               f"'{claimed_name.strip()}' is not them. {left} attempt(s) left before it self-destructs.")
            return False, f"Wrong PIN. {left} attempt(s) left before the room self-destructs."

        if self.guest_key is not None and "recipient" in self.connections:
            return False, "This room is already open on the recipient's other device."

        self.guest_key = secrets.token_hex(16)
        self.last_activity = time.time()
        return True, self.guest_key

    # ------------------------------------------------------------------ messaging
    def peer_of(self, role: str) -> Optional[dict]:
        other = "recipient" if role == "creator" else "creator"
        return self.connections.get(other)

    async def send_to(self, role: str, message) -> bool:
        conn = self.connections.get(role)
        if not conn:
            return False
        try:
            if isinstance(message, (bytes, bytearray)):
                await conn["ws"].send_bytes(message)
            else:
                await conn["ws"].send_json(message)
            return True
        except Exception as e:
            logger.debug(f"Send to {role} in {self.room_id} failed: {e}")
            return False

    async def relay(self, from_role: str, message) -> bool:
        """Forwards an (already end-to-end encrypted) frame to the other peer."""
        self.last_activity = time.time()
        other = "recipient" if from_role == "creator" else "creator"
        return await self.send_to(other, message)

    async def broadcast(self, message: dict):
        for role in list(self.connections):
            await self.send_to(role, message)

    # ------------------------------------------------------------------ presence
    async def attach(self, role: str, ws: WebSocket, alias: str) -> str:
        conn_id = secrets.token_hex(6)
        old = self.connections.get(role)
        self.connections[role] = {"ws": ws, "alias": alias, "conn_id": conn_id}
        self.last_activity = time.time()

        if old:  # Same person reconnected from a fresh socket (refresh / network blip)
            try:
                await old["ws"].close(code=4001, reason="Superseded by a newer connection")
            except Exception:
                pass

        returning = role in self._grace_tasks
        task = self._grace_tasks.pop(role, None)
        if task:
            task.cancel()

        if len(self.connections) == 2:
            self.paired_once = True

        await self.relay(role, {
            "type": "peer_returned" if returning else "peer_joined",
            "alias": alias, "role": role, "timestamp": time.time(),
        })
        return conn_id

    async def detach(self, role: str, conn_id: str):
        conn = self.connections.get(role)
        if not conn or conn["conn_id"] != conn_id or self.is_destroyed:
            return
        self.connections.pop(role)
        logger.info(f"{role} left room {self.room_id}")

        # Chat is over once someone leaves: burn unless they come back within the grace window
        await self.relay(role, {
            "type": "peer_left", "alias": conn["alias"], "role": role,
            "grace": RECONNECT_GRACE_SECONDS, "timestamp": time.time(),
        })
        self._grace_tasks[role] = asyncio.create_task(self._burn_after_grace(role, conn["alias"]))

    async def _burn_after_grace(self, role: str, alias: str):
        try:
            await asyncio.sleep(RECONNECT_GRACE_SECONDS)
        except asyncio.CancelledError:
            return
        self._grace_tasks.pop(role, None)
        if role not in self.connections and not self.is_destroyed:
            await self._on_burn(self.room_id, f"{alias} left the chat. Room auto-destroyed.")

    async def self_destruct(self, reason: str = "Room burned"):
        """Purges all volatile state, closes every socket and forgets every secret."""
        if self.is_destroyed:
            return
        self.is_destroyed = True
        logger.warning(f"VAPORIZING ROOM {self.room_id}: {reason}")

        for task in self._grace_tasks.values():
            task.cancel()
        self._grace_tasks.clear()

        for conn in list(self.connections.values()):
            try:
                await conn["ws"].send_json({"type": "room_vaporized", "reason": reason, "timestamp": time.time()})
                await conn["ws"].close(code=4000, reason="Vaporized")
            except Exception:
                pass
        self.connections.clear()
        self.token = self.host_key = ""
        self.guest_key = None
        self._pin = None
        self.creator_alias = self.target_recipient = ""


class RoomManager:
    def __init__(self):
        self._rooms: Dict[str, EphemeralRoom] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

    def create_room(self, creator_alias: str, target_recipient: str,
                    secret_pin: str = "", ttl_minutes: int = DEFAULT_TTL_MINUTES) -> EphemeralRoom:
        if len(self._rooms) >= MAX_ROOMS:
            raise RuntimeError("Too many active rooms on this device. Try again later.")
        if ttl_minutes not in ALLOWED_TTL_MINUTES:
            ttl_minutes = DEFAULT_TTL_MINUTES

        room_id = secrets.token_urlsafe(9)
        room = EphemeralRoom(room_id, creator_alias or "Host", target_recipient or "Guest",
                             secret_pin, ttl_minutes, on_burn=self.delete_room)
        self._rooms[room_id] = room
        logger.info(f"Created ephemeral room [{room_id}] (ttl {ttl_minutes} min)")
        return room

    def get_room(self, room_id: str) -> Optional[EphemeralRoom]:
        room = self._rooms.get(room_id)
        if room and room.is_destroyed:
            self._rooms.pop(room_id, None)
            return None
        return room

    @property
    def active_count(self) -> int:
        return len(self._rooms)

    async def delete_room(self, room_id: str, reason: str = "Manual purge"):
        room = self._rooms.pop(room_id, None)
        if room:
            await room.self_destruct(reason)

    async def cleanup_loop(self):
        """Background routine: enforce room lifetimes and purge abandoned rooms."""
        while True:
            await asyncio.sleep(10)
            now = time.time()
            for r_id, room in list(self._rooms.items()):
                if room.is_destroyed:
                    self._rooms.pop(r_id, None)
                elif now >= room.expires_at:
                    await self.delete_room(r_id, "Room lifetime expired. Everything was erased.")
                elif not room.connections and not room.paired_once and now - room.last_activity > UNCLAIMED_TIMEOUT_SECONDS:
                    await self.delete_room(r_id, "Room was never used and has been erased.")

    def start_cleanup(self):
        if not self._cleanup_task or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self.cleanup_loop())

    async def shutdown(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
        for r_id in list(self._rooms):
            await self.delete_room(r_id, "Server shutting down. Everything was erased.")


# Global singleton instance
room_manager = RoomManager()
