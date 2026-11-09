import socket
import threading
import time
# pyrefly: ignore[missing-import]
import pytest
from honeypot.tcp_decoy import handle_client

@pytest.fixture
def captured_events(monkeypatch):
    events = []
    def fake_log_event(source_ip, service, event_type, outcome, metadata):
        events.append((source_ip, service, event_type, outcome, metadata))
    monkeypatch.setattr('honeypot.tcp_decoy.log_event', fake_log_event)
    monkeypatch.setattr('honeypot.tcp_decoy.is_blocked', lambda ip: False)
    return events

def test_normal_login(captured_events):
    # create a pair of connected sockets
    srv, cli = socket.socketpair()
    # start server side handling in a thread
    thread = threading.Thread(target=handle_client, args=(srv, ("127.0.0.1", 0)))
    thread.start()
    # client receives the prompt, sends username and password, then reads response
    # read "login: " prompt
    data = cli.recv(1024)
    assert b"login: " in data
    # send username
    cli.sendall(b"bob\n")
    # read "password: " prompt
    data = cli.recv(1024)
    assert b"password: " in data
    # send password
    cli.sendall(b"pw\n")
    # read "Login incorrect" response
    data = cli.recv(1024)
    assert b"Login incorrect" in data
    # close client side to end interaction
    cli.close()
    thread.join(3)
    # verify events captured
    assert len(captured_events) == 2
    conn_evt = captured_events[0]
    login_evt = captured_events[1]
    assert conn_evt[2] == "connection_opened"
    assert login_evt[2] == "login_attempt"
    assert login_evt[4]["username_length"] == 3
    assert login_evt[4]["password_length"] == 2
    # ensure metadata values are numbers, not raw text
    for val in login_evt[4].values():
        assert isinstance(val, int)

def test_oversized_input(captured_events):
    srv, cli = socket.socketpair()
    thread = threading.Thread(target=handle_client, args=(srv, ("127.0.0.1", 0)))
    thread.start()
    try:
        # the decoy may close the connection early, that is fine
        cli.sendall(b"a" * 10000 + b"\n")
    except (BrokenPipeError, ConnectionResetError):
        pass
    cli.close()
    thread.join(3)
    assert not thread.is_alive()
    for event in captured_events:
        for value in event[4].values():
            assert value <= 256

def test_early_close(captured_events):
    srv, cli = socket.socketpair()
    thread = threading.Thread(target=handle_client, args=(srv, ("127.0.0.1", 0)))
    thread.start()
    # client closes immediately without reading anything
    cli.close()
    thread.join(3)
    # only connection_opened event recorded
    assert len(captured_events) == 1
    assert captured_events[0][2] == "connection_opened"
    
    assert not thread.is_alive()
