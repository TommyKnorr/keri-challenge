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
    saider, sad1 = coring.Saider.saidify(sad=dict(sad), code=coring.MtrDex.SHA3_256)
    sad1["d"] = saider.qb64
    return sad1


def digerify(ser: bytes) -> coring.Diger:
    """
    Create a Diger over ser.
    """
    return coring.Diger(ser=ser, code=coring.MtrDex.SHA3_256)


def signature_header(hab, *, ser: bytes) -> dict:
    """
    Build request headers containing a Signature header.
    """
    verfer0 = hab.kever.verfers[0]
    sigers = hab.sign(ser=ser, verfers=[verfer0])

    signage = ending.Signage(
        markers=sigers,
        indexed=True,
        signer=hab.pre,
        ordinal=None,
        digest=None,
        kind="CESR",
    )

    return ending.signature([signage])


def verify_signature_header(signature_value: str, *, ser: bytes, verfers) -> None:
    """
    Verify a Signature header value.
    """
    signages = ending.designature(signature_value)
    assert signages

    signage = signages[0]
    items = list(signage.markers.items())
    assert len(items) == 1

    _, marker = items[0]
    assert verfers[0].verify(sig=marker.raw, ser=ser)


@pytest.fixture(autouse=True)
def _clear_server_memory():
    """
    Ensure server storage is cleared between tests.
    """
    server.reset_storage()


@pytest.fixture()
def paired_habs(tmp_path):
    """
    Provide paired host/requestor Habs isolated per test.
    """
    head_dir = str(tmp_path)

    with (
        make_hab("host", b"0123456789abcdef", head_dir=head_dir) as (_, host),
        make_hab("req", b"abcdef0123456789", head_dir=head_dir) as (_, req),
    ):
        yield host, req


@pytest.fixture()
def falcon_client(paired_habs):
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
    host, req = paired_habs

    body = saidify_sad({"d": "", "i": req.pre, "n": NAME})
    result = falcon_client.simulate_post(
        "/",
        json=body,
        headers=signature_header(req, ser=body["d"].encode("utf-8")),
    )
    assert result.status_code == 200
    assert result.json == body

    qs = "name=" + urllib.parse.quote(NAME, safe="")
    diger = digerify(qs.encode("utf-8"))
    result = falcon_client.simulate_get(
        "/?" + qs,
        headers=signature_header(req, ser=diger.raw),
    )
    assert result.status_code == 200
    assert result.json == body


def test_get_by_aid_and_said(falcon_client, paired_habs):
    host, req = paired_habs

    body = saidify_sad({"d": "", "i": req.pre, "n": NAME})
    falcon_client.simulate_post(
        "/",
        json=body,
        headers=signature_header(req, ser=body["d"].encode("utf-8")),
    )

    qs = "AID=" + urllib.parse.quote(req.pre, safe="")
    diger = digerify(qs.encode("utf-8"))
    result = falcon_client.simulate_get(
        "/?" + qs,
        headers=signature_header(req, ser=diger.raw),
    )
    assert result.status_code == 200
    assert result.json == body

    qs = "SAID=" + urllib.parse.quote(body["d"], safe="")
    diger = digerify(qs.encode("utf-8"))
    result = falcon_client.simulate_get(
        "/?" + qs,
        headers=signature_header(req, ser=diger.raw),
    )
    assert result.status_code == 200
    assert result.json == body


def test_bad_signature_fails(falcon_client, paired_habs):
    _, req = paired_habs

    body = saidify_sad({"d": "", "i": req.pre, "n": NAME})
    good = signature_header(req, ser=body["d"].encode("utf-8"))["Signature"]

    bad = good.replace('0="', '0="A', 1)
    result = falcon_client.simulate_post("/", json=body, headers={"Signature": bad})
    assert result.status_code in (401, 403)
