"""Exercise recovery against a real, isolated OpenSSL CA."""

import argparse
import subprocess

import pytest

from certadmin import config
from certadmin.commands import enroll
from certadmin.lib import crypto, enrollment, registry, util


@pytest.fixture
def ca(tmp_path, monkeypatch):
    monkeypatch.setattr(util, "runtime_state", util.RuntimeState())
    (tmp_path / "private").mkdir()
    (tmp_path / "newcerts").mkdir()
    (tmp_path / "index.txt").write_text("")
    (tmp_path / "serial").write_text("1000\n")
    (tmp_path / "crlnumber").write_text("1000\n")
    config.OPENSSL_CONF.write_text("""
[ca]
default_ca = CA_default
[CA_default]
dir = .
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
crlnumber = $dir/crlnumber
private_key = $dir/private/ca.key
certificate = $dir/certs/ca.pem
default_md = sha256
default_days = 30
default_crl_days = 7
policy = policy
[policy]
commonName = supplied
[usr_cert]
basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
""")
    subprocess.run(
        [
            config.OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            "/CN=Test CA",
            "-days",
            "30",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            str(tmp_path / "private/ca.key"),
            "-out",
            str(tmp_path / "certs/ca.pem"),
        ],
        check=True,
        capture_output=True,
    )
    config.CHAIN_PATH.write_bytes((tmp_path / "certs/ca.pem").read_bytes())
    elsewhere = tmp_path / "unrelated"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    original_run = util.run_cmd

    def run(cmd, **kwargs):
        if "pkcs12" in cmd:
            cmd = [*cmd, "-passout", "pass:test"]
        original_run(cmd, **kwargs)

    monkeypatch.setattr(util, "run_cmd", run)
    original_openssl = enrollment.openssl

    def openssl(*args, **kwargs):
        if args[0] == "pkcs12":
            args = (*args, "-passin", "pass:test")
        return original_openssl(*args, **kwargs)

    monkeypatch.setattr(enrollment, "openssl", openssl)
    return tmp_path


def run_enroll(resume=False):
    enroll.run(argparse.Namespace(user="alice", device="work-laptop", resume=resume))


def test_ca_operations_from_unrelated_directory(ca):
    run_enroll()
    crypto.revoke_cert("alice-work-laptop")
    assert (ca / "index.txt").read_text().startswith("R\t")
    subprocess.run(
        [config.OPENSSL, "crl", "-in", str(config.CRL_PATH), "-noout"], check=True
    )


@pytest.mark.parametrize(
    "stage", ["gen_csr", "sign_cert", "gen_p12", "update_registry"]
)
def test_resume_after_failure_preserves_key_and_issues_once(ca, monkeypatch, stage):
    owner = enroll if stage == "update_registry" else crypto
    original = getattr(owner, stage)

    def fail(*args):
        raise subprocess.CalledProcessError(1, stage)

    monkeypatch.setattr(owner, stage, fail)
    with pytest.raises(subprocess.CalledProcessError):
        run_enroll()
    key = config.CLIENTS_PATH / "alice-work-laptop.key.pem"
    before = key.read_bytes()
    monkeypatch.setattr(owner, stage, original)
    run_enroll(resume=True)
    run_enroll(resume=True)
    assert key.read_bytes() == before
    assert len((ca / "index.txt").read_text().splitlines()) == 1
    assert registry.get_registry_entry("alice-work-laptop")["serial"] == "1000"


def test_missing_output_after_issuance_cannot_issue_again(ca):
    run_enroll()
    (config.ISSUED_CERTS_PATH / "alice-work-laptop.cert.pem").unlink()
    (config.CLIENTS_PATH / "alice-work-laptop.p12").unlink()
    with pytest.raises(ValueError, match="already records"):
        run_enroll(resume=True)
    assert len((ca / "index.txt").read_text().splitlines()) == 1


@pytest.mark.parametrize("damage", ["mismatch", "invalid", "missing", "identity"])
def test_rejects_unusable_material_before_signing(ca, damage):
    key = crypto.gen_key("alice-work-laptop")
    csr = crypto.gen_csr("alice-work-laptop", key)
    if damage == "invalid":
        csr.write_text("broken")
    elif damage == "missing":
        key.unlink()
    elif damage == "identity":
        csr.write_bytes(crypto.gen_csr("other-device", key).read_bytes())
    else:
        key.write_bytes(crypto.gen_key("other-device").read_bytes())
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        run_enroll(resume=True)
    assert (ca / "index.txt").read_text() == ""


def test_dry_run_reports_existing_material_without_subprocess(ca, monkeypatch, capsys):
    crypto.gen_key("alice-work-laptop")
    util.runtime_state.dry_run = True

    def fail(*args, **kwargs):
        pytest.fail("dry-run executed subprocess")

    monkeypatch.setattr(subprocess, "run", fail)
    run_enroll()
    assert "blocked" in capsys.readouterr().out
    run_enroll(resume=True)
    output = capsys.readouterr().out
    assert "Validate and reuse" in output
    assert "Pending validation" in output
    assert (ca / "index.txt").read_text() == ""


def test_resume_rejects_force(ca):
    util.runtime_state.force_overwrite = True
    with pytest.raises(ValueError, match="cannot be combined"):
        run_enroll(resume=True)


def test_existing_files_are_preflighted(ca):
    (config.CLIENTS_PATH / "alice-work-laptop.p12").write_text("existing")
    with pytest.raises(ValueError, match="--resume"):
        run_enroll()
    assert not (config.CLIENTS_PATH / "alice-work-laptop.key.pem").exists()


def test_registry_conflict_does_not_overwrite(ca):
    run_enroll()
    data = registry.load_registry()
    data["alice-work-laptop"]["serial"] = "9999"
    registry.save_registry(data)
    with pytest.raises(ValueError, match="Registry conflicts"):
        run_enroll(resume=True)
    assert registry.load_registry() == data


def test_revoked_certificate_cannot_resume(ca):
    run_enroll()
    crypto.revoke_cert("alice-work-laptop")
    with pytest.raises(ValueError, match="valid CA record"):
        run_enroll(resume=True)


def test_broken_bundle_requires_explicit_reconciliation(ca):
    run_enroll()
    bundle = config.CLIENTS_PATH / "alice-work-laptop.p12"
    bundle.write_bytes(b"incomplete export")
    with pytest.raises(subprocess.CalledProcessError):
        run_enroll(resume=True)
    assert bundle.read_bytes() == b"incomplete export"


def test_force_cannot_replace_issued_material(ca):
    run_enroll()
    key = config.CLIENTS_PATH / "alice-work-laptop.key.pem"
    before = key.read_bytes()
    util.runtime_state.force_overwrite = True
    with pytest.raises(ValueError, match="Cannot force replacement"):
        run_enroll()
    assert key.read_bytes() == before


def test_ca_database_path_comes_from_configuration(ca):
    custom = ca / "custom-index.txt"
    (ca / "index.txt").rename(custom)
    config.OPENSSL_CONF.write_text(
        config.OPENSSL_CONF.read_text().replace(
            "$dir/index.txt", "${dir}/custom-index.txt"
        )
    )
    run_enroll()
    assert custom.read_text().startswith("V\t")


def test_invalid_ca_configuration_stops_before_key_creation(ca):
    config.OPENSSL_CONF.write_text(".include elsewhere.cnf\n")
    with pytest.raises(ValueError, match="Cannot resolve CA state"):
        run_enroll()
    assert not (config.CLIENTS_PATH / "alice-work-laptop.key.pem").exists()


def test_cli_accepts_resume():
    from certadmin.certadmin import build_parser

    args = build_parser().parse_args(["enroll", "--resume", "alice", "work-laptop"])
    assert args.resume


def test_real_signing_failure_reuses_original_key_and_csr(ca):
    configuration = config.OPENSSL_CONF.read_text()
    config.OPENSSL_CONF.write_text(
        configuration.replace(
            "private_key = $dir/private/ca.key",
            "private_key = $dir/private/missing.key",
        )
    )
    with pytest.raises(subprocess.CalledProcessError):
        run_enroll()
    key = config.CLIENTS_PATH / "alice-work-laptop.key.pem"
    csr = config.CLIENTS_PATH / "alice-work-laptop.csr.pem"
    before = (key.read_bytes(), csr.read_bytes())
    config.OPENSSL_CONF.write_text(configuration)
    run_enroll(resume=True)
    assert (key.read_bytes(), csr.read_bytes()) == before
    assert len((ca / "index.txt").read_text().splitlines()) == 1


def test_relative_ca_paths_are_resolved_before_subprocess_chdir(ca, monkeypatch):
    from pathlib import Path

    monkeypatch.setattr(config, "BASE_PATH", Path(".."))
    monkeypatch.setattr(config, "OPENSSL_CONF", Path("../openssl.cnf"))
    monkeypatch.setattr(config, "ISSUED_CERTS_PATH", Path("../issued"))
    monkeypatch.setattr(config, "CLIENTS_PATH", Path("../clients"))
    monkeypatch.setattr(config, "CRL_PATH", Path("../crl/intermediate.crl.pem"))
    run_enroll()
    crypto.revoke_cert("alice-work-laptop")
    assert (ca / "index.txt").read_text().startswith("R\t")


@pytest.mark.parametrize("padding", [" ", "\t"])
def test_resume_accepts_padded_section_names_with_dir_references(ca, padding):
    configuration = config.OPENSSL_CONF.read_text().replace(
        "[ca]", f"[{padding}ca{padding}]"
    ).replace("[CA_default]", f"[{padding}CA_default{padding}]")
    config.OPENSSL_CONF.write_text(configuration)
    key = crypto.gen_key("alice-work-laptop")
    csr = crypto.gen_csr("alice-work-laptop", key)
    before = (key.read_bytes(), csr.read_bytes())

    assert enrollment.ca_paths() == (ca / "index.txt", ca / "certs/ca.pem")
    run_enroll(resume=True)

    assert (key.read_bytes(), csr.read_bytes()) == before
    assert config.OPENSSL_CONF.read_text() == configuration
    assert len((ca / "index.txt").read_text().splitlines()) == 1


def test_normalized_duplicate_sections_are_rejected(ca):
    with config.OPENSSL_CONF.open("a") as configuration:
        configuration.write("\n[ CA_default ]\ndatabase = ./different-index.txt\n")
    with pytest.raises(ValueError, match="Cannot resolve CA state"):
        enrollment.ca_paths()


def test_padded_sections_do_not_allow_ambiguous_ca_state(ca):
    run_enroll()
    config.OPENSSL_CONF.write_text(config.OPENSSL_CONF.read_text().replace(
        "[ca]", "[ ca ]"
    ).replace("[CA_default]", "[ CA_default ]"))
    database = ca / "index.txt"
    database.write_text(database.read_text() * 2)
    before = database.read_bytes()

    with pytest.raises(ValueError, match="single valid CA record"):
        run_enroll(resume=True)
    assert database.read_bytes() == before
