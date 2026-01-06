"""
Programming Challenge – KERI Foundation

Test harness
"""
import urllib.parse
import contextlib
import pytest
from falcon import testing

import server
from keri.app import habbing
from keri.core import coring, signing
from keri.end import ending

NAME = "John Doe"

@contextlib.contextmanager
def make_hab(hab_name: str, salt: bytes, *, head_dir: str):
    """
    Create a Hab under an explicit absolute head directory.

    In keripy/hio:
    - base must be a relative path segment
    - headDirPath is the absolute filesystem root
    """
    # Open a Habery rooted under the provided headDirPath and yield a single-count habitat.
    with habbing.openHby(
        name=hab_name,
        base="keri",
        temp=True,
        salt=signing.Salter(raw=salt).qb64,
        headDirPath=head_dir,
    ) as hby:
        hab = hby.makeHab(name=hab_name, icount=1)
        yield hby, hab


def saidify_sad(sad: dict) -> dict:
    """
    Return a SAIDified copy of sad.
    """
    # Compute SAID and return a modified copy of the SAD with the computed SAID in 'd'.
    saider, sad1 = coring.Saider.saidify(sad=dict(sad), code=coring.MtrDex.SHA3_256)
    sad1["d"] = saider.qb64
    return sad1


def digerify(ser: bytes) -> coring.Diger:
    """
    Create a Diger over ser.
    """
    # Build a SHA3_256 Diger over the provided serialization bytes.
    return coring.Diger(ser=ser, code=coring.MtrDex.SHA3_256)


def sig_header(hab, *, ser: bytes) -> dict:
    """
    Build request headers containing a Signature header.
    """
    # Create a single indexed signature (index 0) over the provided ser using verifier 0.
    verfer0 = hab.kever.verfers[0]
    sigers = hab.sign(ser=ser, verfers=[verfer0])

    # Build Signage in keripy style
    signage = ending.Signage(
        markers=sigers,
        indexed=True,
        signer=hab.pre,
        ordinal=None,
        digest=None,
        kind="CESR",
    )
    # Return the resulting HTTP Signature header dict.
    return ending.signature([signage])


def verify_signature_header(sig: str, *, ser: bytes, verfers) -> None:
    """
    Verify a Signature header value.
    """
    # Parse the Signature header into signages and assert at least one group exists.
    signages = ending.designature(sig)
    assert signages

    # Extract the first group and assert that exactly one marker is present.
    signage = signages[0]
    items = list(signage.markers.items())
    assert len(items) == 1

    # Verify the signature marker against verifier index 0 over the provided ser.
    _, marker = items[0]
    assert verfers[0].verify(sig=marker.raw, ser=ser)


@pytest.fixture(autouse=True)
def _clear_server_memory():
    """
    Ensure server storage is cleared between tests.
    """
    # Reset module-level server storage before each test to enforce isolation.
    server.reset_storage()


@pytest.fixture()
def paired_habs(tmp_path):
    """
    Provide paired host/requestor Habs isolated per test.
    """
    # Create a per-test head directory to keep Habery storage isolated and portable.
    head_dir = str(tmp_path)

    # Construct host and requestor habitats under the same per-test root.
    with (
        make_hab("host", b"0123456789abcdef", head_dir=head_dir) as (_, host),
        make_hab("req", b"abcdef0123456789", head_dir=head_dir) as (_, req),
    ):
        yield host, req


@pytest.fixture()
def falcon_client(paired_habs):
    # Build Falcon app with known verifiers for both requestor and host, then wrap with test client.
    host, req = paired_habs
    app = server.create_app(
        host_hab=host,
        verfers_by_aid={
            req.pre: req.kever.verfers,
            host.pre: host.kever.verfers,
        },
    )
    return testing.TestClient(app)


def test_post_register_and_get_by_name(falcon_client, paired_habs):
    # Unpack habitats for request signing and (optionally) host response verification.
    host, req = paired_habs

    # POST: build SAIDified SAD, sign over SAID, and assert successful echo response.
    body = saidify_sad({"d": "", "i": req.pre, "n": NAME})
    result = falcon_client.simulate_post(
        "/",
        json=body,
        headers=sig_header(req, ser=body["d"].encode("utf-8")),
    )
    assert result.status_code == 200
    assert result.json == body

    # GET by name: build query string, digerify it, sign over diger raw, and assert returned record matches.
    qs = "name=" + urllib.parse.quote(NAME, safe="")
    diger = digerify(qs.encode("utf-8"))
    result = falcon_client.simulate_get(
        "/?" + qs,
        headers=sig_header(req, ser=diger.raw),
    )
    assert result.status_code == 200
    assert result.json == body


def test_get_by_aid_and_said(falcon_client, paired_habs):
    # Unpack habitats for request signing and setup.
    host, req = paired_habs

    # Seed the registry with a POST so subsequent GET lookups succeed.
    body = saidify_sad({"d": "", "i": req.pre, "n": NAME})
    falcon_client.simulate_post(
        "/",
        json=body,
        headers=sig_header(req, ser=body["d"].encode("utf-8")),
    )

    # GET by AID: sign over diger(raw(query_string)) and assert returned record matches.
    qs = "AID=" + urllib.parse.quote(req.pre, safe="")
    diger = digerify(qs.encode("utf-8"))
    result = falcon_client.simulate_get(
        "/?" + qs,
        headers=sig_header(req, ser=diger.raw),
    )
    assert result.status_code == 200
    assert result.json == body

    # GET by SAID: sign over diger(raw(query_string)) and assert returned record matches.
    qs = "SAID=" + urllib.parse.quote(body["d"], safe="")
    diger = digerify(qs.encode("utf-8"))
    result = falcon_client.simulate_get(
        "/?" + qs,
        headers=sig_header(req, ser=diger.raw),
    )
    assert result.status_code == 200
    assert result.json == body


def test_bad_signature_fails(falcon_client, paired_habs):
    # Use the requestor habitat to create a valid signature then tamper it to force failure.
    _, req = paired_habs

    # POST with a deliberately corrupted Signature header should be rejected (401/403).
    body = saidify_sad({"d": "", "i": req.pre, "n": NAME})
    good = sig_header(req, ser=body["d"].encode("utf-8"))["Signature"]

    bad = good.replace('0="', '0="A', 1)
    result = falcon_client.simulate_post("/", json=body, headers={"Signature": bad})
    assert result.status_code in (401, 403)
