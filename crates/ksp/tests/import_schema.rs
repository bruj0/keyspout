//! The mock secret service, exercised directly.
//!
//! # Why this has its own test
//!
//! A fixture that is never tested can be broken in a way that makes the test
//! relying on it pass for the wrong reason — a service that serves nothing looks
//! the same as a validator that accepted nothing. These tests pin the three
//! properties the end-to-end test depends on: the port is ephemeral, both modes
//! serve what they claim, and the listener is gone after the guard drops.
//!
//! # The port assertion
//!
//! Two services started at once must get different ports. Asserting only that the
//! port is non-zero would pass for a hardcoded 8080 that collided with a developer's
//! own server — the failure the ephemeral bind exists to prevent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fixtures {
    pub mod mock_secret_service;
}

use fixtures::mock_secret_service::{MockService, Mode};

#[test]
fn two_services_started_together_get_different_ports() {
    let first = MockService::start(Mode::Correct).expect("the first service binds");
    let second = MockService::start(Mode::Correct).expect("the second service binds");

    assert_ne!(
        first.port(),
        second.port(),
        "each service must bind its own ephemeral port, or parallel tests collide"
    );
    assert_ne!(first.port(), 0, "the reported port must be the bound one");
}

#[test]
fn the_correct_mode_serves_a_json_object() {
    let service = MockService::start(Mode::Correct).expect("it binds");
    let body = get(&service, "/items");

    let value: serde_json::Value =
        serde_json::from_str(&body).expect("the correct mode serves valid JSON");
    assert!(
        value.is_object(),
        "the declared shape is an object; got {value}"
    );
    assert!(
        value["items"].is_array(),
        "the list operation reads an `items` array; got {value}"
    );
}

#[test]
fn the_wrong_shape_mode_serves_something_that_is_not_json() {
    // The switch exists so the shape refusal can be tested against a real
    // response. If this mode served valid JSON, the refusal test would pass while
    // proving nothing.
    let service = MockService::start(Mode::WrongShape).expect("it binds");
    let body = get(&service, "/items");
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).is_err(),
        "the wrong-shape mode must serve something that is not JSON; got {body:?}"
    );
}

#[test]
fn the_service_records_the_request_it_received() {
    // The end-to-end test asserts the declaration's selector reached the service.
    // That assertion is only meaningful if the service records what arrived.
    let service = MockService::start(Mode::Correct).expect("it binds");
    let _ = get(&service, "/items?search=team1");

    let requests = service.requests();
    assert_eq!(requests.len(), 1, "one request, one record: {requests:?}");
    assert!(
        requests[0].line.contains("search=team1"),
        "the record must hold the path and query verbatim; got {:?}",
        requests[0].line
    );
}

#[test]
fn the_listener_is_gone_after_the_guard_drops() {
    // The acceptance criterion: no test leaves a listener behind. Binding the same
    // port again is the only way to prove it from inside the process.
    let port = {
        let service = MockService::start(Mode::Correct).expect("it binds");
        service.port()
    };

    let rebound = std::net::TcpListener::bind(("127.0.0.1", port));
    assert!(
        rebound.is_ok(),
        "the port must be free after the service drops, or a later test inherits a \
         listener it did not start"
    );
}

/// One GET, so the three tests above do not each hand-roll a socket.
fn get(service: &MockService, path: &str) -> String {
    use std::io::{Read, Write};

    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", service.port())).expect("the service accepts");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .expect("the request is written");
    stream.flush().expect("it flushes");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("the response is read");

    // The body is everything after the blank line that ends the headers.
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}
