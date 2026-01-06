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

    # Convert internal record fields back into the required SAD shape.
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
def sig_header(hab, *, ser: bytes) -> str:
    """
    Build HTTP Signature header value.
    - indexed signatures only
    - exactly one signature entry at index 0
    """
    # Select the single verifier (index 0) and create a single indexed signature over ser.
    verfer0 = hab.kever.verfers[0] # exactly one siger, index 0
    sigers = hab.sign(ser=ser, verfers=[verfer0])

    # Build a Signage describing the signature group in the same style as keripy's ending helpers.
    signage = ending.Signage(
        markers=sigers,
        indexed=True,
        signer=hab.pre,
        ordinal=None,
        digest=None,
        kind="CESR",
    )

    # Serialize Signage into an HTTP Signature header value and validate it is present and non-empty.
    header = ending.signature([signage])
    sig = header.get("Signature")
    if not isinstance(sig, str) or not sig.strip():
        raise RuntimeError("ending.signature() did not return a viable Signature header value")

    # Return the finalized Signature header value.
    return sig.strip()


def parse_sig_header(sig: str) -> ending.Signage:
    """
    Parse HTTP Signature header value into a Signage object.
    Returns expected single signature.
    """
    # Reject missing/empty Signature header values early.
    if not isinstance(sig, str) or not sig.strip():
        raise falcon.HTTPUnauthorized(title="Missing Signature")

    # Parse the Signature header into one or more Signage groups (keripy designature format).
    try:
        signages = ending.designature(sig.strip())
    except Exception as ex:
        raise falcon.HTTPUnauthorized(title="Bad Signature", description=str(ex))

    # Require at least one signature group.
    if not signages:
        raise falcon.HTTPUnauthorized(title="Bad Signature", description="No signature groups found")

    # Return the first signature group (this service expects a single group).
    return signages[0]


def indexed_siger(signage: ending.Signage):
    """
    Extract sole indexed Siger (index 0) from a Signage.
    """
    # Require exactly one marker entry because this project uses a single indexed signature (index 0).
    items = list(signage.markers.items())
    if len(items) != 1:
        raise falcon.HTTPUnauthorized(
            title="Bad Signature",
            description="Expected exactly one indexed signature",
        )

    # Validate the marker tag is an integer index and specifically index 0.
    tag, marker = items[0]
    try:
        tagi = int(tag)
    except Exception:
        raise falcon.HTTPUnauthorized(title="Bad Signature", description="Invalid signature tag")

    # Enforce that both the marker's embedded index and the tag agree on index 0.
    idx = getattr(marker, "index", getattr(marker, "indx", None))
    if tagi != 0 or idx != 0:
        raise falcon.HTTPUnauthorized(
            title="Bad Signature",
            description="Expected indexed signature at index 0",
        )

    # Return the single indexed signature marker.
    return marker


def verify_sig(signage: ending.Signage, *, ser: bytes, verfers) -> None:
    """
    Verify the single indexed signature over ser.

    - Raises falcon HTTP errors on failure.
    - Returns None on success.
    """
    # Extract the single indexed signature marker (index 0) from the Signage.
    siger = indexed_siger(signage)

    # Ensure the caller provided at least one verifier to check against.
    if not verfers:
        raise falcon.HTTPUnauthorized(title="Bad Signature", description="No verifiers available")

    # Verify signature using verifier index 0 and raise if verification fails.
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
        # Store the host habitat and a lookup of known verifiers keyed by signer AID.
        self.host = host_hab
        self.verfers_by_aid = verfers_by_aid

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        # Parse and validate request JSON as a dict SAD.
        sad = req.media
        if not isinstance(sad, dict):
            raise falcon.HTTPBadRequest(title="Invalid JSON")

        # Validate required SAD fields are present.
        for field in ("d", "i", "n"):
            if field not in sad:
                raise falcon.HTTPBadRequest(title="Invalid SAD", description=f"Missing '{field}'")

        # Normalize the SAD fields to strings for comparison and storage.
        said = str(sad["d"])
        aid = str(sad["i"])
        name = str(sad["n"])

        # Recompute SAID from the SAD and ensure 'd' matches the computed value.
        saider, _ = coring.Saider.saidify(sad=dict(sad), code=coring.MtrDex.SHA3_256)
        if said != saider.qb64:
            raise falcon.HTTPBadRequest(title="Invalid SAID")

        # Parse the Signature header and ensure the claimed signer matches the SAD 'i' field.
        signage = parse_sig_header(req.get_header("Signature"))
        if signage.signer != aid:
            raise falcon.HTTPUnauthorized(title="Signer mismatch")

        # Resolve the requestor's verifiers and reject unknown signers.
        verfers = self.verfers_by_aid.get(aid)
        if not verfers:
            raise falcon.HTTPUnauthorized(title="Unknown signer")

        # Verify the request signature over the SAID value.
        verify_sig(signage, ser=said.encode("utf-8"), verfers=verfers)

        # Insert the record into each in-memory index for lookup by SAID, AID, and name.
        rec = Record(said=said, aid=aid, name=name)
        _BY_SAID[said] = rec
        _BY_AID[aid] = rec
        _BY_NAME[name] = rec

        # Build the response body and host Signature header over the response SAID.
        resp.media = rec.as_sad()
        resp.status = falcon.HTTP_200
        resp.set_header("Signature", sig_header(self.host, ser=said.encode("utf-8")))

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        # Compute a Diger over the raw query string for request signature coverage.
        qs = req.query_string or ""
        diger = coring.Diger(ser=qs.encode("utf-8"), code=coring.MtrDex.SHA3_256)

        # Parse the Signature header and require an explicit signer in the signage.
        signage = parse_sig_header(req.get_header("Signature"))
        signer = signage.signer
        if not signer:
            raise falcon.HTTPUnauthorized(title="Missing signer")

        # Resolve verifiers for the signer and reject unknown signers.
        verfers = self.verfers_by_aid.get(signer)
        if not verfers:
            raise falcon.HTTPUnauthorized(title="Unknown signer")

        # Verify the request signature over the diger raw bytes.
        verify_sig(signage, ser=diger.raw, verfers=verfers)

        # Extract query parameters; exactly one of name/AID/SAID must be provided.
        name = req.get_param("name")
        aid = req.get_param("AID")
        said = req.get_param("SAID")

        # Validate the caller provided exactly one selector parameter.
        params = [p for p in (name, aid, said) if p is not None]
        if len(params) != 1:
            raise falcon.HTTPBadRequest(
                title="Invalid query",
                description="Provide exactly one of name, AID, or SAID",
            )

        # Perform the appropriate in-memory lookup based on the provided selector.
        rec: Optional[Record]
        if name is not None:
            rec = _BY_NAME.get(name)
        elif aid is not None:
            rec = _BY_AID.get(aid)
        else:
            rec = _BY_SAID.get(said)

        # Return 404 if no matching record was found.
        if rec is None:
            raise falcon.HTTPNotFound(title="Not found")

        # Return the SAD and include a host signature over the returned SAID.
        resp.media = rec.as_sad()
        resp.status = falcon.HTTP_200
        resp.set_header("Signature", sig_header(self.host, ser=rec.said.encode("utf-8")))


def create_app(*, host_hab, verfers_by_aid: Dict[str, Any]) -> falcon.App:
    """
    Falcon app factory.
    """
    # Construct Falcon app and attach the single route for the registry resource.
    app = falcon.App()
    app.add_route("/", RegistryResource(host_hab, verfers_by_aid))
    return app