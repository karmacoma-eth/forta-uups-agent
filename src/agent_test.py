
from unittest.mock import Mock
from forta_agent import create_transaction_event, get_web3_provider
from .agent import handle_transaction, Web3Provider
from dataclasses import dataclass, field


@dataclass
class UpgradeEventValue:
    implementation: str = '0x8888888888888888888888888888888888888888'

@dataclass
class UpgradeEvent:
    """Class for keeping track of an item in inventory."""
    address: str = '0x4242424242424242424242424242424242424242'
    blockNumber: int = 42
    args: UpgradeEventValue = UpgradeEventValue()

mock_tx_event = create_transaction_event({})
mock_tx_event.filter_log = Mock()

web3_provider = Web3Provider()
web3_provider.get_code = Mock()


class TestUupsVulnAgent:
    def test_no_findings_when_code_still_present(self):
        mock_tx_event.filter_log.return_value = [UpgradeEvent()]
        web3_provider.get_code.return_value = 'code'

        findings = handle_transaction(mock_tx_event, web3=web3_provider)
        assert len(findings) == 0


    def test_findings_when_code_not_present(self):
        mock_tx_event.filter_log.return_value = [UpgradeEvent()]
        web3_provider.get_code.return_value = ''

        findings = handle_transaction(mock_tx_event, web3=web3_provider)
        assert len(findings) == 1


    def test_multiple_findings_with_multiple_events(self):
        old_impl1 = '0x1111111111111111111111111111111111111111'
        old_impl2 = '0x2222222222222222222222222222222222222222'
        mock_tx_event.filter_log.return_value = [
            UpgradeEvent(address=old_impl1),
            UpgradeEvent(address=old_impl2)
        ]

        web3_provider.get_code.return_value = ''
        findings = handle_transaction(mock_tx_event, web3=web3_provider)
        assert len(findings) == 2
        assert findings[0].metadata['old_impl'] == old_impl1
        assert findings[1].metadata['old_impl'] == old_impl2
