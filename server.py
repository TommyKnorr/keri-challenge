"""
Programming Challenge KERI Foundation

Falcon based Server
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence

import falcon
from keri.core import coring
from keri.end import ending


@dataclass(frozen=True)
class Record:
    """
    In-memory record stored/returned as a SAD.
    """
    said: str
    aid: str
    name: str
    def as_sad(self) -> Dict[str, str]:
        return {"d": self.said, "i": self.aid, "n": self.name}


# module-level storage
_BY_SAID: Dict[str, Record] = {}
_BY_AID: Dict[str, Record] = {}
_BY_NAME: Dict[str, Record] = {}

def reset_storage() -> None:
    """
    Clear in-memory storage.
    """
    _BY_SAID.clear()
    _BY_AID.clear()
    _BY_NAME.clear()

# --------------------------------------
# Helpers
# --------------------------------------
def signature_header(hab, *, ser: bytes) -> str:
    """
    Build HTTP Signature header value.
    - indexed signatures only
    - exactly one signature entry at index 0
    """
    verfer0 = hab.kever.verfers[0] # exactly one siger, index 0
    sigers = hab.sign(ser=ser, verfers=[verfer0])

    signage = ending.Signage(
        markers=sigers,
        indexed=True,
        signer=hab.pre,
        ordinal=None,
        digest=None,
        kind="CESR",
    )

    header = ending.signature([signage])
    signature = header.get("Signature")
    if not isinstance(signature, str) or not signature.strip():
        raise RuntimeError("ending.signature() did not return a viable Signature header value")

    return signature.strip()


def parse_signature_header(signature_value: str) -> ending.Signage:
    """
    Parse HTTP Signature header value into a Signage object.
    Returns expected single signature.
    """
    if not isinstance(signature_value, str) or not signature_value.strip():
        raise falcon.HTTPUnauthorized(title="Missing Signature")

    try:
        signages = ending.designature(signature_value.strip())
    except Exception as ex:
        raise falcon.HTTPUnauthorized(title="Bad Signature", description=str(ex))

    if not signages:
        raise falcon.HTTPUnauthorized(title="Bad Signature", description="No signature groups found")

    return signages[0]


def indexed_siger(signage: ending.Signage):
    """
    Extract sole indexed Siger (index 0) from a Signage.
    """
    items = list(signage.markers.items())
    if len(items) != 1:
        raise falcon.HTTPUnauthorized(
            title="Bad Signature",
            description="Expected exactly one indexed signature",
        )

    tag, marker = items[0]
    try:
        tagi = int(tag)
    except Exception:
        raise falcon.HTTPUnauthorized(title="Bad Signature", description="Invalid signature tag")

    idx = getattr(marker, "index", getattr(marker, "indx", None))
    if tagi != 0 or idx != 0:
        raise falcon.HTTPUnauthorized(
            title="Bad Signature",
            description="Expected indexed signature at index 0",
        )

    return marker


def verify_signature(signage: ending.Signage, *, ser: bytes, verfers) -> None:
    """
    Verify the single indexed signature over ser.

    - Raises falcon HTTP errors on failure.
    - Returns None on success.
    """
    siger = indexed_siger(signage)

    if not verfers:
        raise falcon.HTTPUnauthorized(title="Bad Signature", description="No verifiers available")

    verfer0 = verfers[0]
    if not verfer0.verify(sig=siger.raw, ser=ser):
        raise falcon.HTTPUnauthorized(title="Bad Signature", description="Signature verification failed")


# --------------------------------------
# Falcon Resources
# --------------------------------------
class RegistryResource:
    """
    Falcon resource implementing POST register and GET query/lookup.
    """
    def __init__(self, host_hab, verfers_by_aid: Dict[str, Sequence[Any]]):
        self.host = host_hab
        self.verfers_by_aid = verfers_by_aid

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        sad = req.media
        if not isinstance(sad, dict):
            raise falcon.HTTPBadRequest(title="Invalid JSON")

        for field in ("d", "i", "n"):
            if field not in sad:
                raise falcon.HTTPBadRequest(title="Invalid SAD", description=f"Missing '{field}'")

        said = str(sad["d"])
        aid = str(sad["i"])
        name = str(sad["n"])

        saider, _ = coring.Saider.saidify(sad=dict(sad), code=coring.MtrDex.SHA3_256)
        if said != saider.qb64:
            raise falcon.HTTPBadRequest(title="Invalid SAID")

        signage = parse_signature_header(req.get_header("Signature"))
        if signage.signer != aid:
            raise falcon.HTTPUnauthorized(title="Signer mismatch")

        verfers = self.verfers_by_aid.get(aid)
        if not verfers:
            raise falcon.HTTPUnauthorized(title="Unknown signer")

        verify_signature(signage, ser=said.encode("utf-8"), verfers=verfers)

        rec = Record(said=said, aid=aid, name=name)
        _BY_SAID[said] = rec
        _BY_AID[aid] = rec
        _BY_NAME[name] = rec

        resp.media = rec.as_sad()
        resp.status = falcon.HTTP_200
        resp.set_header("Signature", signature_header(self.host, ser=said.encode("utf-8")))

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        qs = req.query_string or ""
        diger = coring.Diger(ser=qs.encode("utf-8"), code=coring.MtrDex.SHA3_256)

        signage = parse_signature_header(req.get_header("Signature"))
        signer = signage.signer
        if not signer:
            raise falcon.HTTPUnauthorized(title="Missing signer")

        verfers = self.verfers_by_aid.get(signer)
        if not verfers:
            raise falcon.HTTPUnauthorized(title="Unknown signer")

        verify_signature(signage, ser=diger.raw, verfers=verfers)

        name = req.get_param("name")
        aid = req.get_param("AID")
        said = req.get_param("SAID")

        params = [p for p in (name, aid, said) if p is not None]
        if len(params) != 1:
            raise falcon.HTTPBadRequest(
                title="Invalid query",
                description="Provide exactly one of name, AID, or SAID",
            )

        rec: Optional[Record]
        if name is not None:
            rec = _BY_NAME.get(name)
        elif aid is not None:
            rec = _BY_AID.get(aid)
        else:
            rec = _BY_SAID.get(said)

        if rec is None:
            raise falcon.HTTPNotFound(title="Not found")

        resp.media = rec.as_sad()
        resp.status = falcon.HTTP_200
        resp.set_header("Signature", signature_header(self.host, ser=rec.said.encode("utf-8")))


def create_app(*, host_hab, verfers_by_aid: Dict[str, Any]) -> falcon.App:
    """
    Falcon app factory.
    """
    app = falcon.App()
    app.add_route("/", RegistryResource(host_hab, verfers_by_aid))
    return app