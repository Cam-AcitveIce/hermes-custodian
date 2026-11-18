"""Expected peer disconnects are quiet; application failures remain visible."""
from http.server import BaseHTTPRequestHandler
import pytest
from custodian.web import _DashboardRequestHandler


@pytest.mark.parametrize('error', [BrokenPipeError, ConnectionResetError, ConnectionAbortedError])
def test_disconnected_browser_during_response_closes_request(monkeypatch, error):
    handler = object.__new__(_DashboardRequestHandler)
    class DisconnectedWriter:
        def write(self, body): raise error('synthetic browser disconnected')
    handler.wfile = DisconnectedWriter()
    handler.send_response = lambda *a: None
    handler._send_security_headers = lambda: None
    handler.send_header = lambda *a: None
    handler.end_headers = lambda: None
    monkeypatch.setattr(BaseHTTPRequestHandler, 'handle', lambda self: self._send_json(200, {'synthetic': True}))
    handler.handle()
    assert handler.close_connection is True


def test_unrelated_server_failure_is_not_hidden(monkeypatch):
    handler = object.__new__(_DashboardRequestHandler)
    def failure(self): raise ValueError('synthetic application failure')
    monkeypatch.setattr(BaseHTTPRequestHandler, 'handle', failure)
    with pytest.raises(ValueError, match='synthetic application failure'):
        handler.handle()
