//! Exit criterion E2 (IAM-03, IAM-06, IAM-09, OPS-22): signing in to a real `tenko serve`,
//! through the public API, the way the sign-in page does.
//!
//! 1. The PIN preset of the Home profile end to end (IAM-03): setup with the PIN, sign out,
//!    sign in with the PIN, and a wrong PIN refused with `auth.invalid_credentials`.
//! 2. TOTP end to end (IAM-06): enrol an authenticator app, sign out, sign in with the
//!    password and a code, and a wrong code and a replayed code refused.
//! 3. A passkey in each TLS mode the harness can start (IAM-06, OPS-22), with the software
//!    authenticator of `tenko-auth` playing the browser and the security key: register a
//!    passkey for the administrator, sign out, sign in with the assertion, and the session
//!    reports the passkey strength. One test per mode, with the origin and the relying-party
//!    ID the mode implies:
//!    - `Plain` is the reverse-proxy mode (OPS-22 c). The browser's origin is the public
//!      `https://localhost`; the proxy, the loopback address, reaches Tenko over plain HTTP
//!      and says so in `X-Forwarded-Proto` and `X-Forwarded-Host`. The relying-party ID is
//!      `tls.public_host`.
//!    - `InternalCa` (OPS-22 a) and `Imported` (OPS-22 b) serve HTTPS on `localhost`; the
//!      browser's origin is `https://localhost:<port>` and the relying-party ID is the host
//!      name from first-run setup.
//!
//! IAM-09 (the break-glass account, usable with a hardware key only) needs an attested,
//! not backup-eligible security key and the account itself; the tests of `tenko-auth` and of
//! the authentication routes cover it, and these tests do not.

mod serve_support;

use reqwest::{Method, header::HeaderMap};
use serde_json::{Value, json};
use serve_support::{
    ADMIN, Node, PASSWORD, Proc, Transport,
    api::{Api, Reply},
    wait_for_setup_token,
};
use tenko_auth::{
    service::{
        WebAuthnLoginFinish, WebAuthnLoginOptions, WebAuthnRegisterFinish, WebAuthnRegisterOptions,
    },
    testing::authenticator::{SoftAttestation, SoftAuthenticator, SoftKeyAlg},
};

/// The origin of the browser in the reverse-proxy mode: the public name, no port.
const PUBLIC_ORIGIN: &str = "https://localhost";

/// A PIN that is not the administrator's.
const WRONG_PIN: &str = "000001";

/// The way a browser reaches the node.
struct Proxy {
    runtime: tokio::runtime::Runtime,
    client: reqwest::Client,
}

/// A browser: an API client that keeps the session cookie of every answer, either
/// straight to the node or through a reverse proxy that terminates TLS.
struct Browser {
    api: Api,
    proxy: Option<Proxy>,
}

impl Browser {
    /// A browser that talks to the node's own origin.
    fn direct(api: Api) -> Self {
        Self { api, proxy: None }
    }

    /// A browser on the public origin `https://localhost` behind a reverse proxy on the
    /// loopback address, which forwards over plain HTTP.
    fn behind_proxy(api: Api) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("an HTTP client");
        Self {
            api,
            proxy: Some(Proxy { runtime, client }),
        }
    }

    /// The origin the page runs on, which the authenticator signs into the client data.
    fn origin(&self) -> String {
        match self.proxy {
            Some(_) => PUBLIC_ORIGIN.to_owned(),
            None => self.api.origin().to_owned(),
        }
    }

    /// One request through the proxy; `forwarded` adds the headers of a proxy.
    fn proxied(&self, method: &Method, path: &str, body: Option<&Value>, forwarded: bool) -> Reply {
        let proxy = self.proxy.as_ref().expect("a browser behind a proxy");
        let mut request = proxy
            .client
            .request(method.clone(), self.api.url(path))
            .header("Origin", PUBLIC_ORIGIN);
        if forwarded {
            request = request
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", "localhost")
                .header("X-Forwarded-For", "198.51.100.7");
        }
        if let Some(cookie) = self.api.cookie() {
            request = request.header("Cookie", cookie);
        }
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(body).expect("JSON"));
        }
        proxy.runtime.block_on(async {
            let response = request
                .send()
                .await
                .unwrap_or_else(|error| panic!("{method} {path}: {error:?}"));
            let status = response.status().as_u16();
            let headers: HeaderMap = response.headers().clone();
            let text = response.text().await.expect("a readable body");
            Reply {
                status,
                headers,
                text,
            }
        })
    }

    /// Keeps, or drops, the session cookie a reply sets.
    fn keep_session(&mut self, reply: &Reply) {
        for value in reply.headers.get_all("set-cookie") {
            let Ok(text) = value.to_str() else { continue };
            let pair = text.split(';').next().unwrap_or_default().trim();
            if let Some(secret) = pair.strip_prefix("tenko_session=") {
                self.api
                    .set_cookie((!secret.is_empty()).then(|| pair.to_owned()));
            }
        }
    }

    fn get(&self, path: &str) -> Reply {
        match self.proxy {
            Some(_) => self.proxied(&Method::GET, path, None, true),
            None => self.api.get(path),
        }
    }

    fn post(&mut self, path: &str, body: &Value) -> Reply {
        let reply = match self.proxy {
            Some(_) => self.proxied(&Method::POST, path, Some(body), true),
            None => self.api.post_unkeyed(path, body),
        };
        self.keep_session(&reply);
        reply
    }

    /// The password step of a login as the administrator.
    fn password_step(&mut self, password: &str) -> Reply {
        self.post(
            "/auth/login/password",
            &json!({ "user_name": ADMIN, "password": password }),
        )
    }

    /// Ends the session.
    fn sign_out(&mut self) {
        let reply = self.post("/auth/logout", &json!({}));
        assert!(
            reply.status < 300,
            "sign-out: HTTP {} {}",
            reply.status,
            reply.text
        );
        assert!(
            self.api.cookie().is_none(),
            "the answer to a sign-out removes the session cookie"
        );
    }

    /// Asserts that the browser has no session.
    #[track_caller]
    fn assert_signed_out(&self) {
        let reply = self.get("/auth/session");
        assert_eq!(reply.status, 401, "a signed-out browser: {}", reply.text);
        assert_eq!(reply.code().as_deref(), Some("auth.unauthenticated"));
    }

    /// The session of the browser (`GET /auth/session`).
    #[track_caller]
    fn session(&self) -> Value {
        self.get("/auth/session").expect(200)
    }
}

/// Starts a node on `transport`, completes first-run setup under the Home profile with the
/// PIN, and returns the browser signed in by setup.
fn installed(transport: Transport) -> (Node, Proc, Api) {
    let mut node = Node::new().with_transport(transport);
    let server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    (node, server, api)
}

/// Asserts that the answer sets a session cookie with the flags of the OPS-22 modes: the
/// secret is `HttpOnly`, `SameSite=Strict` and `Secure`, since every mode but plain HTTP
/// serves, or is told that it serves, HTTPS.
#[track_caller]
fn assert_session_cookie_flags(reply: &Reply) {
    let cookies: Vec<String> = reply
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|text| text.starts_with("tenko_session="))
        .map(str::to_owned)
        .collect();
    assert_eq!(
        cookies.len(),
        1,
        "exactly one session cookie is set: {cookies:?}"
    );
    for flag in ["HttpOnly", "SameSite=Strict", "Secure"] {
        assert!(
            cookies[0].contains(flag),
            "the session cookie carries {flag}: {}",
            cookies[0].split('=').next().unwrap_or_default()
        );
    }
}

/// IAM-03, E2: the PIN preset of the Home profile, end to end. A PIN is the administrator's
/// password; sign-in with it gives a session of PIN strength, and a wrong PIN is refused with
/// the documented code and no session.
#[test]
fn e2_iam_03_the_pin_preset_signs_in_and_a_wrong_pin_is_refused() {
    let (node, _server, api) = installed(Transport::Plain);
    let mut browser = Browser::direct(api);

    // Setup signed the administrator in with the PIN.
    let session = browser.session();
    assert_eq!(session["strength"], "pin", "{session}");
    assert_eq!(session["profile"], "home", "{session}");
    assert_eq!(session["user"]["name"], ADMIN, "{session}");
    let settings = browser.get("/settings/security").expect(200);
    assert_eq!(
        settings["settings"]["password_policy"]["preset"], "pin",
        "the Home profile selects the PIN preset (TGL-01): {settings}"
    );

    // The preset accepts digits only.
    let letters = browser
        .post(
            "/auth/password/check",
            &json!({ "password": "a long passphrase with words" }),
        )
        .expect(200);
    assert_eq!(letters["acceptable"], false, "{letters}");
    assert_eq!(letters["policy"]["preset"], "pin", "{letters}");
    let digits = browser
        .post("/auth/password/check", &json!({ "password": "482916" }))
        .expect(200);
    assert_eq!(digits["acceptable"], true, "{digits}");

    // Sign out; the session is gone.
    browser.sign_out();
    browser.assert_signed_out();

    // A wrong PIN is refused with the documented code, and sets no session.
    let wrong = browser.password_step(WRONG_PIN);
    assert_eq!(wrong.status, 401, "a wrong PIN: {}", wrong.text);
    assert_eq!(wrong.code().as_deref(), Some("auth.invalid_credentials"));
    assert!(
        wrong.headers.get("set-cookie").is_none(),
        "a refused sign-in sets no cookie"
    );
    browser.assert_signed_out();

    // The right PIN signs in, with PIN strength, one failure later.
    let step = browser.password_step(PASSWORD);
    let body = step.expect(200);
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(body["session"]["strength"], "pin", "{body}");
    assert_session_cookie_flags(&step);
    let session = browser.session();
    assert_eq!(session["strength"], "pin", "{session}");
    assert_eq!(session["user"]["name"], ADMIN, "{session}");

    // The command-line client signs in with the same PIN.
    node.login().assert_code(0);
}

/// IAM-06, E2: TOTP end to end. After enrolment the password alone is no longer enough:
/// the sign-in asks for a code, refuses a wrong one and a replayed one, and a fresh code
/// gives a session of password-and-TOTP strength.
#[test]
fn e2_iam_06_totp_enrols_and_signs_in_and_a_wrong_or_replayed_code_is_refused() {
    let (_node, _server, api) = installed(Transport::Plain);
    let mut browser = Browser::direct(api);

    let mut totp = browser.api.enrol_totp();
    browser.sign_out();
    browser.assert_signed_out();

    // The password step asks for the second factor and sets no session.
    let step = browser.password_step(PASSWORD);
    let first = step.expect(200);
    assert_eq!(first["status"], "second_factor", "{first}");
    assert!(
        first["methods"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| method == "totp")),
        "the sign-in offers TOTP: {first}"
    );
    assert!(
        step.headers.get("set-cookie").is_none(),
        "the password alone sets no session"
    );
    browser.assert_signed_out();
    let challenge = first["challenge_id"].clone();

    // A wrong code is refused with the documented code.
    let wrong = browser.post(
        "/auth/login/totp",
        &json!({ "challenge_id": challenge, "code": "000000" }),
    );
    assert_eq!(wrong.status, 401, "a wrong code: {}", wrong.text);
    assert_eq!(wrong.code().as_deref(), Some("auth.invalid_credentials"));
    browser.assert_signed_out();

    // A fresh code completes the same challenge.
    let code = totp.code();
    let done = browser.post(
        "/auth/login/totp",
        &json!({ "challenge_id": challenge, "code": code }),
    );
    let body = done.expect(200);
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(body["session"]["strength"], "password_totp", "{body}");
    assert_session_cookie_flags(&done);
    assert_eq!(browser.session()["strength"], "password_totp");

    // The same code, replayed in a new sign-in, is refused.
    browser.sign_out();
    let again = browser.password_step(PASSWORD).expect(200);
    assert_eq!(again["status"], "second_factor", "{again}");
    let replay = browser.post(
        "/auth/login/totp",
        &json!({ "challenge_id": again["challenge_id"], "code": code }),
    );
    assert_eq!(replay.status, 401, "a replayed code: {}", replay.text);
    assert_eq!(replay.code().as_deref(), Some("auth.invalid_credentials"));
    browser.assert_signed_out();
}

/// Registers a passkey for the signed-in administrator, signs out, signs in with the
/// assertion and checks the session. The authenticator signs the browser's origin; the
/// relying-party ID must be `localhost` in every mode.
fn passkey_round_trip(mut browser: Browser) {
    let origin = browser.origin();
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);

    // Register: the options name the relying party, the authenticator answers for the
    // browser's origin.
    let start = browser
        .post(
            "/auth/webauthn/register/start",
            &json!({ "label": "Laptop" }),
        )
        .expect(200);
    let options: WebAuthnRegisterOptions =
        serde_json::from_value(start).expect("the registration options");
    assert_eq!(
        options.public_key.rp.id, "localhost",
        "the relying-party ID is the host name of the mode"
    );
    let credential = authenticator.register(&options.public_key, &origin);
    let finish = browser.post(
        "/auth/webauthn/register/finish",
        &serde_json::to_value(WebAuthnRegisterFinish {
            ceremony_id: options.ceremony_id,
            credential,
        })
        .expect("JSON"),
    );
    let enrolled = finish.expect(200);
    assert_eq!(enrolled["credential"]["label"], "Laptop", "{enrolled}");
    let listed = browser.get("/auth/webauthn/credentials").expect(200);
    assert_eq!(
        listed["items"].as_array().map(Vec::len),
        Some(1),
        "the administrator has one passkey: {listed}"
    );

    browser.sign_out();
    browser.assert_signed_out();

    // A page on another origin cannot use the passkey: the assertion is refused and no
    // session starts.
    let start = browser
        .post("/auth/webauthn/login/start", &json!({ "user_name": ADMIN }))
        .expect(200);
    let options: WebAuthnLoginOptions = serde_json::from_value(start).expect("the login options");
    let foreign = authenticator.assert(&options.public_key, "https://phish.example.test");
    let refused = browser.post(
        "/auth/webauthn/login/finish",
        &serde_json::to_value(WebAuthnLoginFinish {
            ceremony_id: options.ceremony_id,
            credential: foreign,
        })
        .expect("JSON"),
    );
    assert_eq!(refused.status, 400, "a foreign origin: {}", refused.text);
    assert_eq!(
        refused.code().as_deref(),
        Some("auth.webauthn.origin_mismatch")
    );
    browser.assert_signed_out();

    // The assertion for the real origin signs in, with passkey strength.
    let start = browser
        .post("/auth/webauthn/login/start", &json!({ "user_name": ADMIN }))
        .expect(200);
    let options: WebAuthnLoginOptions = serde_json::from_value(start).expect("the login options");
    assert_eq!(options.public_key.rp_id, "localhost");
    assert_eq!(
        options.public_key.allow_credentials.len(),
        1,
        "the login offers the administrator's passkey"
    );
    let assertion = authenticator.assert(&options.public_key, &origin);
    let login = browser.post(
        "/auth/webauthn/login/finish",
        &serde_json::to_value(WebAuthnLoginFinish {
            ceremony_id: options.ceremony_id,
            credential: assertion,
        })
        .expect("JSON"),
    );
    let body = login.expect(200);
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(body["session"]["strength"], "passkey", "{body}");
    assert_session_cookie_flags(&login);
    let session = browser.session();
    assert_eq!(session["strength"], "passkey", "{session}");
    assert_eq!(session["user"]["name"], ADMIN, "{session}");
}

/// OPS-22 (c), IAM-06, E2: a passkey behind a reverse proxy. The server runs in the
/// reverse-proxy mode with the loopback address as the trusted proxy and `localhost` as the
/// public host; the browser's origin is `https://localhost`, which only the forwarded
/// headers of the trusted proxy make the origin of the request.
#[test]
fn e2_ops_22_iam_06_a_passkey_signs_in_behind_a_reverse_proxy() {
    let (_node, _server, api) = installed(Transport::Plain);
    let browser = Browser::behind_proxy(api);

    // Without the proxy's headers the public origin is foreign: the CSRF guard refuses it.
    let direct = browser.proxied(
        &Method::POST,
        "/auth/login/password",
        Some(&json!({ "user_name": ADMIN, "password": WRONG_PIN })),
        false,
    );
    assert_eq!(direct.status, 403, "{}", direct.text);
    assert_eq!(direct.code().as_deref(), Some("sys.csrf_rejected"));
    // With them, the same request is a request on `https://localhost`, and is judged on
    // its merits.
    let forwarded = browser.proxied(
        &Method::POST,
        "/auth/login/password",
        Some(&json!({ "user_name": ADMIN, "password": WRONG_PIN })),
        true,
    );
    assert_eq!(forwarded.status, 401, "{}", forwarded.text);

    // Setup left a session cookie in the client; use it behind the proxy.
    let session = browser.session();
    assert_eq!(session["strength"], "pin", "{session}");
    passkey_round_trip(browser);
}

/// OPS-22 (a), IAM-06, E2: a passkey over HTTPS with a certificate from the internal CA,
/// on `https://localhost:<port>`.
#[test]
fn e2_ops_22_iam_06_a_passkey_signs_in_with_the_internal_ca() {
    let (_node, _server, api) = installed(Transport::InternalCa);
    assert!(
        api.origin().starts_with("https://localhost:"),
        "{}",
        api.origin()
    );
    passkey_round_trip(Browser::direct(api));
}

/// OPS-22 (b), IAM-06, E2: a passkey over HTTPS with an imported certificate (a leaf of a
/// test CA for `localhost`), on `https://localhost:<port>`.
#[test]
fn e2_ops_22_iam_06_a_passkey_signs_in_with_an_imported_certificate() {
    let (_node, _server, api) = installed(Transport::Imported);
    assert!(
        api.origin().starts_with("https://localhost:"),
        "{}",
        api.origin()
    );
    passkey_round_trip(Browser::direct(api));
}
