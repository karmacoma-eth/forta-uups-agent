'''
This agent alerts when it finds evidence that a UUPS upgradeable contract was self-destructed.

See the detailed description in the post-mortem:
https://forum.openzeppelin.com/t/uupsupgradeable-vulnerability-post-mortem/15680
'''

from forta_agent import Finding, FindingType, FindingSeverity, get_web3_provider
from constants import ERC1967_UPGRADE_EVENT_ABI

web3 = get_web3_provider()

def handle_transaction(transaction_event):
    '''Look for Upgraded(address) events coming from an address that no longer contains code'''
    findings = []
    upgrade_events = transaction_event.filter_log(ERC1967_UPGRADE_EVENT_ABI)

    for event in upgrade_events:
        old_impl_address = web3.toChecksumAddress(event.address)

        # Retrieve the code at the old implementation address as it was in the block of the event.
        # If we retrieve it at the current block, we may get a false positive (if the contract
        # was later destroyed but not because of this upgrade)
        old_impl_code = web3.eth.get_code(old_impl_address, block_identifier=event.blockNumber)

        if not old_impl_code:
            new_impl_address = web3.toChecksumAddress(event.args.implementation)

            findings.append(Finding({
                'name': 'UUPSUpgradeable Vulnerability Self-Destruct Exploit',
                'description': f'Self-destructed implementation: {old_impl_address}',
                'alert_id': 'SUS-1',
                'type': FindingType.Exploit,
                'severity': FindingSeverity.Critical,
                'metadata': {
                    'old_impl': old_impl_address,
                    'new_impl': new_impl_address
                }
            }))

    return findings
