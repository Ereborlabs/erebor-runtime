#!/usr/bin/env python3

import argparse
import base64
import hashlib
import http.server
import json
import secrets
import ssl
import subprocess
import time
import urllib.parse


def base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class Provider(http.server.BaseHTTPRequestHandler):
    codes = {}
    issuer = ""
    private_key = ""
    modulus = ""

    def log_message(self, message, *args):
        print(message % args, flush=True)

    def json_response(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/.well-known/openid-configuration":
            self.json_response(200, {
                "issuer": self.issuer,
                "authorization_endpoint": self.issuer + "/authorize",
                "token_endpoint": self.issuer + "/token",
                "jwks_uri": self.issuer + "/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["openid", "email", "profile"],
                "claims_supported": ["aud", "email", "exp", "iat", "iss", "nonce", "sub"],
            })
            return
        if parsed.path == "/jwks":
            self.json_response(200, {"keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "mithril-vm",
                "n": self.modulus,
                "e": "AQAB",
            }]})
            return
        if parsed.path == "/authorize":
            query = urllib.parse.parse_qs(parsed.query)
            required = ["client_id", "code_challenge", "nonce", "redirect_uri", "state"]
            if any(len(query.get(name, [])) != 1 for name in required):
                self.send_error(400, "incomplete authorization request")
                return
            if query["client_id"][0] != "mithril-vm" or query.get("response_type") != ["code"]:
                self.send_error(400, "invalid authorization client")
                return
            code = secrets.token_urlsafe(24)
            self.codes[code] = {
                "challenge": query["code_challenge"][0],
                "nonce": query["nonce"][0],
                "redirect_uri": query["redirect_uri"][0],
            }
            redirect = urllib.parse.urlparse(query["redirect_uri"][0])
            values = urllib.parse.parse_qsl(redirect.query, keep_blank_values=True)
            values.extend((("code", code), ("state", query["state"][0])))
            location = urllib.parse.urlunparse(redirect._replace(query=urllib.parse.urlencode(values)))
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        if parsed.path == "/healthz":
            self.json_response(200, {"ready": True})
            return
        self.send_error(404)

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/token":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        code = form.get("code", [""])[0]
        verifier = form.get("code_verifier", [""])[0]
        record = self.codes.pop(code, None)
        challenge = base64url(hashlib.sha256(verifier.encode()).digest())
        if (record is None or challenge != record["challenge"]
                or form.get("redirect_uri", [""])[0] != record["redirect_uri"]):
            self.json_response(400, {"error": "invalid_grant"})
            return
        now = int(time.time())
        header = base64url(json.dumps({
            "alg": "RS256", "kid": "mithril-vm", "typ": "JWT"
        }, separators=(",", ":")).encode())
        claims = base64url(json.dumps({
            "iss": self.issuer,
            "sub": "mithril-vm-operator",
            "aud": "mithril-vm",
            "exp": now + 300,
            "iat": now,
            "nonce": record["nonce"],
            "email": "operator@mithril.invalid",
            "email_verified": True,
        }, separators=(",", ":")).encode())
        signed = (header + "." + claims).encode()
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.private_key],
            input=signed,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.json_response(200, {
            "access_token": secrets.token_urlsafe(24),
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": signed.decode() + "." + base64url(signature),
        })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:9444")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--issuer", required=True)
    args = parser.parse_args()
    host, port = args.listen.rsplit(":", 1)
    modulus = subprocess.run(
        ["openssl", "rsa", "-in", args.private_key, "-noout", "-modulus"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip().split("=", 1)[1]
    Provider.issuer = args.issuer
    Provider.private_key = args.private_key
    Provider.modulus = base64url(bytes.fromhex(modulus))
    server = http.server.ThreadingHTTPServer((host, int(port)), Provider)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.certificate, args.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("OIDC fixture ready", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
