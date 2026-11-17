# Copyright 2026 Sitelabs.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""TLS between the servers: the checks at startup, and a real mutual-TLS call through urllib and
httpx, with a CA and certificates the test makes."""
import datetime
import http.server
import ipaddress
import ssl
import threading
from contextlib import contextmanager

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from graph_security import internal_tls
from graph_security.settings import SecuritySettings


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, key, cert):
    path.with_suffix(".pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.with_name(path.name + "-key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(path.with_suffix(".pem")), str(path.with_name(path.name + "-key.pem"))


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("test CA")).issuer_name(_name("test CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    (d / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    out = {"ca": str(d / "ca.pem")}
    for name, sans in [("server", ["127.0.0.1", "graph-server"]), ("client", ["client"])]:
        key = ec.generate_private_key(ec.SECP256R1())
        alt = [x509.IPAddress(ipaddress.ip_address(s)) if s[0].isdigit() else x509.DNSName(s) for s in sans]
        cert = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(ca.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName(alt), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                                                      x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        out[name] = _write(d / name, key, cert)
    return out


@contextmanager
def mutual_tls_server(pki):
    """An https server that requires a client certificate from the CA; it answers with the client's name."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            cn = dict(x[0] for x in self.connection.getpeercert()["subject"])["commonName"]
            body = cn.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=pki["ca"])
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(*pki["server"])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def client(pki, **more):
    return SecuritySettings(internal_tls_ca_file=pki["ca"], internal_tls_certfile=pki["client"][0],
                            internal_tls_keyfile=pki["client"][1], **more)


def test_a_call_over_mutual_tls_through_urllib_and_httpx(pki):
    with mutual_tls_server(pki) as port:
        url = f"https://127.0.0.1:{port}/"
        assert internal_tls.opener(client(pki)).open(url, timeout=5).read() == b"client"
        with internal_tls.httpx_client(client(pki)) as c:
            assert c.get(url).text == "client"
        no_cert = SecuritySettings(internal_tls_ca_file=pki["ca"])
        with pytest.raises(Exception):
            internal_tls.opener(no_cert).open(url, timeout=5).read()          # the server needs a client certificate
        with pytest.raises(Exception):
            internal_tls.opener(SecuritySettings(internal_tls_certfile=pki["client"][0],
                                                 internal_tls_keyfile=pki["client"][1])).open(url, timeout=5)  # not the system's CAs


def test_a_certificate_is_checked_against_internal_tls_server_name(pki):
    with mutual_tls_server(pki) as port:
        url = f"https://127.0.0.1:{port}/"
        named = client(pki, internal_tls_server_name="graph-server")
        assert internal_tls.opener(named).open(url, timeout=5).read() == b"client"
        with internal_tls.httpx_client(named) as c:
            assert c.get(url).text == "client"
        assert internal_tls.httpx_extensions(named) == {"sni_hostname": "graph-server"}
        with pytest.raises(Exception):
            internal_tls.opener(client(pki, internal_tls_server_name="someone-else")).open(url, timeout=5)


def test_what_stops_a_server_starting(pki, tmp_path):
    p = internal_tls.problems
    assert p(SecuritySettings(), {}) == []
    assert any("no such file" in e for e in p(SecuritySettings(internal_tls_ca_file=str(tmp_path / "none")), {}))
    assert any("UVICORN_SSL_CERT_REQS=maybe" in e for e in p(SecuritySettings(uvicorn_ssl_cert_reqs="maybe"), {}))
    assert any("needs UVICORN_SSL_CERTFILE and UVICORN_SSL_CA_CERTS" in e
               for e in p(SecuritySettings(uvicorn_ssl_cert_reqs="required"), {}))
    assert any("INTERNAL_TLS_KEYFILE is set without" in e for e in p(SecuritySettings(internal_tls_keyfile=pki["ca"]), {}))
    required = SecuritySettings(internal_tls_required=True)
    errors = p(required, {"REPLICATION_SOURCE_URL": ["http://10.0.0.1:5050", "https://10.0.0.2:5050"]})
    assert any("must speak https" in e for e in errors)
    assert any("REPLICATION_SOURCE_URL must be https:// (http://10.0.0.1:5050)" in e for e in errors)
    assert not any("must speak https" in e for e in p(required, {}, serves=False))
    assert any("can't be used" in e for e in p(SecuritySettings(internal_tls_ca_file=pki["client"][1]), {}))
    serving = SecuritySettings(uvicorn_ssl_certfile=pki["server"][0], uvicorn_ssl_keyfile=pki["server"][1],
                               uvicorn_ssl_ca_certs=pki["ca"], uvicorn_ssl_cert_reqs="required", internal_tls_required=True)
    assert p(serving, {"X": ["https://a"]}) == []
    assert internal_tls.uvicorn_options(serving)["ssl_cert_reqs"] == ssl.CERT_REQUIRED and internal_tls.scheme(serving) == "https"
    assert internal_tls.uvicorn_options(SecuritySettings()) == {} and internal_tls.scheme(SecuritySettings()) == "http"
    assert internal_tls.metrics_server_options(client(pki))["client_auth_required"]


def test_urls_kept_as_http_become_https():
    m = internal_tls.upgrade_members({"partitions": ["http://a:1", "https://b:2"], "instances": {"http://a:1": "i-1"}})
    assert m == {"partitions": ["https://a:1", "https://b:2"], "instances": {"https://a:1": "i-1"}}
    assert httpx.__version__
