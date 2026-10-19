import io
import json
import base64
import ipaddress
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import qrcode

from config import get_primary_ip, get_all_interfaces, has_internet, DEFAULT_PORT, logger
from rooms import room_manager, DEFAULT_TTL_MINUTES, RECONNECT_GRACE_SECONDS, ROLES

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Frames the server forwards untouched between the two peers. Their content is
# end-to-end encrypted in the browser; the server only sees opaque blobs.
RELAY_TYPES = {"msg", "typing", "receipt", "file_header", "file_complete", "file_cancel", "file_ack", "nudge"}
MAX_TEXT_FRAME = 256 * 1024
MAX_BINARY_FRAME = 2 * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing CipherDrop engine...")
    room_manager.start_cleanup()
    logger.info(f"==> LAN address:   http://{get_primary_ip()}:{DEFAULT_PORT}")
    logger.info(f"==> This computer: http://localhost:{DEFAULT_PORT}")
    yield
    await room_manager.shutdown()
    logger.info("CipherDrop shut down. All rooms erased.")


app = FastAPI(title="CipherDrop", lifespan=lifespan)


class CreateRoomRequest(BaseModel):
    creator_alias: str = Field(default="Host", max_length=32)
    target_recipient: str = Field(min_length=1, max_length=32)
    secret_pin: str = Field(default="", max_length=32)
    selected_ip: str = Field(default="", max_length=64)
    ttl_minutes: int = DEFAULT_TTL_MINUTES


class VerifyAccessRequest(BaseModel):
    room_id: str = Field(max_length=32)
    token: str = Field(max_length=64)
    claimed_name: str = Field(max_length=32)
    pin: str = Field(default="", max_length=32)
    guest_key: str = Field(default="", max_length=64)


class VaporizeRequest(BaseModel):
    room_id: str = Field(max_length=32)
    key: str = Field(max_length=64)
    reason: str = Field(default="", max_length=120)


def generate_qr_base64(data: str) -> str:
    """Renders the room link as a PNG QR. Dark modules on white with a quiet zone so every phone camera reads it."""
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0a0e17", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _require_room(room_id: str, token: str):
    room = room_manager.get_room(room_id)
    if not room or room.is_destroyed or not room.check_token(token):
        raise HTTPException(status_code=404, detail="This room has been vaporized or never existed.")
    return room


@app.get("/api/network-info")
async def get_network_info():
    """Interfaces the host can broadcast on (Wi-Fi, Hotspot, Bluetooth PAN, LAN) and whether internet is up."""
    return {
        "primary_ip": get_primary_ip(),
        "port": DEFAULT_PORT,
        "interfaces": get_all_interfaces(),
        "online": has_internet(),
        "active_rooms": room_manager.active_count,
    }


@app.post("/api/create-room")
async def create_room(req: CreateRoomRequest):
    """Creates an ephemeral 1-to-1 room locked to one named recipient and returns its QR code."""
    chosen_ip = req.selected_ip.strip() or get_primary_ip()
    try:
        ipaddress.IPv4Address(chosen_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid broadcast IP address.")

    try:
        room = room_manager.create_room(
            creator_alias=req.creator_alias.strip() or "Host",
            target_recipient=req.target_recipient.strip(),
            secret_pin=req.secret_pin,
            ttl_minutes=req.ttl_minutes,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    room_url = f"http://{chosen_ip}:{DEFAULT_PORT}/?room={room.room_id}&token={room.token}"
    return {
        "success": True,
        "room_id": room.room_id,
        "token": room.token,
        "host_key": room.host_key,
        "creator_alias": room.creator_alias,
        "target_recipient": room.target_recipient,
        "has_pin": room.has_pin,
        "room_url": room_url,
        "qr_data_url": generate_qr_base64(room_url),
        "expires_in": room.expires_in,
    }


@app.get("/api/room-info/{room_id}")
async def get_room_info(room_id: str, token: str = Query(default="")):
    """Pre-join info. Deliberately does NOT reveal who the room is for, so Y/Z can't just type X's name."""
    room = _require_room(room_id, token)
    return {
        "room_id": room.room_id,
        "creator_alias": room.creator_alias,
        "has_pin": room.has_pin,
        "status": room.status,
        "expires_in": room.expires_in,
    }


@app.post("/api/verify-access")
async def verify_access(req: VerifyAccessRequest):
    """Lets only the designated recipient in. Unauthorized names count towards the self-destruct lockout."""
    room = _require_room(req.room_id, req.token)
    ok, result = room.verify_recipient(req.claimed_name, req.pin, req.guest_key)

    if not ok:
        await room.send_to("creator", {
            "type": "intrusion",
            "attempts": room.failed_attempts,
            "claimed_name": req.claimed_name.strip()[:32],
        })
        if result.startswith("SECURITY PURGE"):
            await room_manager.delete_room(room.room_id, "Intruder lockout: too many unauthorized unlock attempts.")
        raise HTTPException(status_code=403, detail=result)

    return {
        "success": True,
        "role": "recipient",
        "guest_key": result,
        "room_id": room.room_id,
        "creator_alias": room.creator_alias,
        "target_recipient": room.target_recipient,
        "expires_in": room.expires_in,
    }


@app.post("/api/vaporize")
async def vaporize_room(req: VaporizeRequest):
    """Panic burn. Requires the creator's or recipient's private key - holding the link alone is not enough."""
    room = room_manager.get_room(req.room_id)
    if not room:
        return {"success": True, "message": "Room already destroyed."}
    role = room.check_member_key(req.key)
    if not role:
        raise HTTPException(status_code=403, detail="Not a member of this room.")
    await room_manager.delete_room(req.room_id, req.reason or f"Room burned by the {role}.")
    return {"success": True, "message": "Room permanently vaporized."}


@app.websocket("/ws/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str):
    """
    Real-time relay. Text frames carry encrypted chat/control messages, binary frames carry
    encrypted file chunks that are streamed straight to the other peer (never stored).
    """
    room = room_manager.get_room(room_id)
    await websocket.accept()
    if not room or room.is_destroyed:
        await websocket.send_json({"type": "room_vaporized", "reason": "This room no longer exists."})
        await websocket.close(code=4004)
        return

    role = None
    conn_id = None
    try:
        auth = await websocket.receive_json()
        role = auth.get("role")
        key = auth.get("key", "")

        authorised = (
            auth.get("type") == "auth" and role in ROLES and room.check_token(auth.get("token", ""))
            and (room.check_host_key(key) if role == "creator" else room.check_guest_key(key))
        )
        if not authorised:
            await websocket.send_json({"type": "auth_failed", "message": "Access denied for this room."})
            await websocket.close(code=4003)
            return

        alias = room.creator_alias if role == "creator" else room.target_recipient
        conn_id = await room.attach(role, websocket, alias)
        peer = room.peer_of(role)
        await websocket.send_json({
            "type": "auth_success",
            "role": role,
            "alias": alias,
            "creator_alias": room.creator_alias,
            "target_recipient": room.target_recipient,
            "peer": {"alias": peer["alias"]} if peer else None,
            "expires_in": room.expires_in,
            "grace": RECONNECT_GRACE_SECONDS,
            "failed_attempts": room.failed_attempts,
        })

        while True:
            frame = await websocket.receive()
            if frame["type"] == "websocket.disconnect":
                break
            if room.is_destroyed:
                break

            data_bytes = frame.get("bytes")
            if data_bytes is not None:
                if len(data_bytes) <= MAX_BINARY_FRAME:
                    await room.relay(role, data_bytes)
                continue

            text = frame.get("text")
            if not text or len(text) > MAX_TEXT_FRAME:
                continue
            try:
                data = json.loads(text)
            except ValueError:
                continue
            msg_type = data.get("type")

            if msg_type in RELAY_TYPES:
                data["from"] = role
                delivered = await room.relay(role, data)
                if msg_type == "msg" and not delivered:
                    await websocket.send_json({"type": "undelivered", "id": data.get("id")})
            elif msg_type == "end_chat":
                await room_manager.delete_room(room_id, data.get("reason") or f"{alias} ended the chat. Everything was erased.")
                break
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong", "expires_in": room.expires_in})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error in room {room_id}: {e}")
    finally:
        if role and conn_id and not room.is_destroyed:
            await room.detach(role, conn_id)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(STATIC_DIR / "assets" / "logo.svg", media_type="image/svg+xml")


# Frontend (mounted last so /api and /ws take precedence)
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    primary_ip = get_primary_ip()
    print("=" * 65)
    print("      [+] CIPHERDROP // EPHEMERAL SECURE QR CHAT [+]")
    print(f"  Share on Wi-Fi / Hotspot / Bluetooth:  http://{primary_ip}:{DEFAULT_PORT}")
    print(f"  Open on this computer:                 http://localhost:{DEFAULT_PORT}")
    print("=" * 65)
    # access_log off: request lines would otherwise print room tokens to the console
    uvicorn.run(app, host="0.0.0.0", port=DEFAULT_PORT, reload=False,
                ws_max_size=4 * 1024 * 1024, access_log=False)
