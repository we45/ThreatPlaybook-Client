import pytest
from playbook.cli import configure, project, apply, login, feature, set_project, get, delete, change_password
from click.testing import CliRunner
from os import remove
    

def test_configure():
    runner = CliRunner()
    result = runner.invoke(configure, ['--host', 'http://localhost', '--port', 5042])
    assert result.exit_code == 0


def test_login():
    runner = CliRunner()
    result = runner.invoke(login, ['--email', 'admin@admin.com', '--password', 'supersecret'])
    assert result.exit_code == 0


def test_set_project():
    runner = CliRunner()
    result = runner.invoke(set_project, ['--name', 'test-project'])
    assert result.exit_code == 0


# def test_create_project():
#     runner = CliRunner()
#     result = runner.invoke(apply, ['project', '--name', 'test-project'])
#     print(result.output)
#     assert result.exit_code == 0


def test_load_file():
    runner = CliRunner()
    result = runner.invoke(apply, ['feature', '--name', '/Users/abhaybhargav/Documents/code/python/ThreatPlaybook-Client/cases/login.yaml'])
    # you need to change paths when you run on your machine
    print(result.output)
    assert result.exit_code == 0


def test_get_feature_specific():
    runner = CliRunner()
    result = runner.invoke(get, ['feature', '--name', 'login_user'])
    print(result.output)
    assert result.exit_code == 0


def test_get_abuser_story():
    runner = CliRunner()
    result = runner.invoke(get, ['abuser-story', '--name', 'external_attacker_account_takeover'])
    print(result.output)
    assert result.exit_code == 0


def test_get_feature_generic():
    runner = CliRunner()
    result = runner.invoke(get, ['feature'])
    print(result.output)
    assert result.exit_code == 0

def test_delete_threat_scenario():
    runner = CliRunner()
    result = runner.invoke(delete, ['scenario', '--name', 'sql injection user account access', '--confirm'])
    print(result.output)
    assert result.exit_code == 0

def test_delete_abuser_story():
    runner = CliRunner()
    result = runner.invoke(delete, ['abuser-story', '--name', 'external_attacker_account_takeover', '--confirm'])
    print(result.output)
    assert result.exit_code == 0

def test_delete_feature():
    runner = CliRunner()
    result = runner.invoke(delete, ['feature', '--name', 'login_user', '--confirm'])
    print(result.output)
    assert result.exit_code == 0


def test_change_password():
    runner = CliRunner()
    result = runner.invoke(change_password, ['--email', 'admin@admin.com', '--old', 'supersecret', '--new', 'supersecret', '--confirm', 'supersecret'])
    print(result.output)
    assert result.exit_code == 0


def test_delete_cred_file():
    try:
        remove('.cred')
        print("deleted cred file")
    except Exception as e:
        print(e)