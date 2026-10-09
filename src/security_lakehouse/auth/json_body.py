"""Check JSON bytes before FastAPI/Pydantic or a mutation sees them."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from security_lakehouse import api_contract as api_v1
from security_lakehouse.strict_json import InvalidJSON, loads

MAX_BODY_BYTES = 5 * 1024 * 1024


class StrictJSONMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self.app(scope, receive, send)
            return
        media_type = dict(scope["headers"]).get(b"content-type", b"").split(b";", 1)[0].strip().lower()
        if media_type and media_type != b"application/json" and not media_type.endswith(b"+json"):
            await self.app(scope, receive, send)
            return
        raw = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            raw.extend(message.get("body", b""))
            if len(raw) > MAX_BODY_BYTES:
                response = JSONResponse(
                    api_v1.error_envelope("payload_too_large", "request body too large"), status_code=413
                )
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        if raw.strip():
            try:
                loads(bytes(raw))
            except InvalidJSON:
                response = JSONResponse(api_v1.error_envelope("bad_request", "invalid JSON body"), status_code=400)
                await response(scope, receive, send)
                return
        consumed = False

        async def replay():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(raw), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
