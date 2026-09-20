from pathlib import Path
import json
import plistlib

from core.domain.rules import HIGH_RISK_KEYWORDS

ROOT = Path(__file__).parents[1]


def test_desktop_risk_vocabulary_matches_existing_core():
    assert set(json.loads((ROOT / 'desktop/rules/high-risk-keywords.json').read_text())) == HIGH_RISK_KEYWORDS


def test_mac_entitlements_have_no_network_or_broad_directory_access():
    with (ROOT / 'desktop/entitlements.plist').open('rb') as f:
        assert plistlib.load(f) == {
            'com.apple.security.app-sandbox': True,
            'com.apple.security.files.user-selected.read-write': True,
            'com.apple.security.files.bookmarks.app-scope': True,
        }
