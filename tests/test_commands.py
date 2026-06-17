"""Tests for command handlers using preloaded test registry."""

from pathlib import Path
from io import StringIO
import sys

import pytest

from commands import list_certs, show


def test_list_all_certificates(capsys):
    """List all certificates from preloaded registry."""
    list_certs.run(type('Args', (), {'active': False, 'revoked': False, 'exposed': False, 'unexposed': False})())
    captured = capsys.readouterr()
    
    assert "active-exposed-iphone" in captured.out
    assert "active-exposed-laptop" in captured.out
    assert "active-unexposed-ipad" in captured.out
    assert "revoked-phone" in captured.out


def test_list_active_only(capsys):
    """List only active certificates."""
    list_certs.run(type('Args', (), {'active': True, 'revoked': False, 'exposed': False, 'unexposed': False})())
    captured = capsys.readouterr()
    
    assert "active-exposed-iphone" in captured.out
    assert "active-unexposed-ipad" in captured.out
    assert "revoked-phone" not in captured.out


def test_list_revoked_only(capsys):
    """List only revoked certificates."""
    list_certs.run(type('Args', (), {'active': False, 'revoked': True, 'exposed': False, 'unexposed': False})())
    captured = capsys.readouterr()
    
    assert "revoked-phone" in captured.out
    assert "revoked-tablet" in captured.out
    assert "active-exposed-iphone" not in captured.out


def test_show_certificate(capsys):
    """Show details of a certificate."""
    show.run(type('Args', (), {'common_name': 'active-exposed-iphone'})())
    captured = capsys.readouterr()
    
    assert "active-exposed-iphone" in captured.out
    assert "active" in captured.out
    assert "exposed-iphone" in captured.out
    assert "1001" in captured.out
    assert "False" in captured.out  # revoked status


def test_show_nonexistent_certificate():
    """Show details fails for nonexistent certificate."""
    with pytest.raises(ValueError):
        show.run(type('Args', (), {'common_name': 'does-not-exist'})())
