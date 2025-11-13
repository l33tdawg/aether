// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";

interface IAccessControl {
    function role(bytes4 _selector, address _contract) external pure returns (bytes32 roleId);
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
    function getRoleMember(bytes32 role, uint256 index) external view returns (address);
    function hasRole(bytes32 role, address account) external view returns (bool);
}

/// @title Check Cap Upgrade Access
/// @notice Verifies who has upgrade permissions for Cap contracts
contract CheckCapUpgradeAccess is Script {
    // Mainnet addresses from config
    address constant ACCESS_CONTROL = 0x7731129a10d51e18cDE607C5C115F26503D2c683;
    address constant CAP_TOKEN = 0xcCcc62962d17b8914c62D74FfB843d73B2a3cccC;
    address constant STAKED_CAP_TOKEN = 0x88887bE419578051FF9F4eb6C858A951921D8888;
    
    function run() external view {
        console.log("=== Cap Contracts Upgrade Access Verification ===\n");
        
        IAccessControl ac = IAccessControl(ACCESS_CONTROL);
        
        // Check CapToken upgrade access
        console.log("1. CapToken (cUSD):", CAP_TOKEN);
        checkUpgradeAccess(ac, CAP_TOKEN);
        
        console.log("\n2. StakedCapToken (stcUSD):", STAKED_CAP_TOKEN);
        checkUpgradeAccess(ac, STAKED_CAP_TOKEN);
    }
    
    function checkUpgradeAccess(IAccessControl ac, address target) internal view {
        // bytes4(0) is the selector used for upgrade authorization
        bytes32 upgradeRole = ac.role(bytes4(0), target);
        console.log("   Upgrade Role ID:", vm.toString(upgradeRole));
        
        uint256 memberCount = ac.getRoleMemberCount(upgradeRole);
        console.log("   Number of addresses with upgrade access:", memberCount);
        
        if (memberCount == 0) {
            console.log("   WARNING: No one has upgrade access!");
            console.log("   FINDING: Contract is UPGRADEABLE but NO ONE can upgrade it");
            console.log("   This could be intentional (renounced) or a deployment error");
            return;
        }
        
        console.log("   Addresses with upgrade access:");
        for (uint256 i = 0; i < memberCount; i++) {
            address member = ac.getRoleMember(upgradeRole, i);
            console.log("   -", member);
            
            // Check if it's an EOA or contract
            uint256 codeSize;
            assembly {
                codeSize := extcodesize(member)
            }
            
            if (codeSize == 0) {
                console.log("     Type: EOA (Externally Owned Account)");
                console.log("     RISK: HIGH - Single private key can upgrade contract!");
            } else {
                console.log("     Type: Contract (likely multisig or governance)");
                console.log("     RISK: Depends on contract security");
            }
        }
    }
}

