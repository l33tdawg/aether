#!/usr/bin/env python3
"""
RocketPool contract addresses on Ethereum mainnet.
These can be dynamically queried from RocketStorage or hardcoded.
"""

# Core RocketPool addresses
ROCKET_STORAGE = "0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46"

# Known contract addresses (EIP-55 checksummed for Solidity compatibility)
ROCKETPOOL_ADDRESSES = {
    "RocketStorage": "0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46",
    "RocketVault": "0x3bDC69C4E5e13E52A65f5583c23EFB9636b469d6",
    "RocketAuctionManager": "0x1a2F00D187C9388fDa3Bf2dc46a6b4740849EcCE",  # Checksummed
    "RocketDAONodeTrustedProposals": "0xb0ec3F657ef43A615aB480FA8D5A53BF2c2f05d5",
    "RocketDAOProposal": "0x1e94e6131Ba5B4F193d2A1067517136C52ddF102",
    "RocketNetworkPrices": "0x25E54Bf48369b8FB25bB79d3a3Ff7F3BA448E382",
    "RocketNetworkBalances": "0x07FCaBCbe4ff0d80c2b1eb42855C0131b6cba2F4",
    "RocketNetworkFees": "0xf824e2d69dc7e7c073162C2bdE87dA4746d27a0f",
    "RocketNetworkVoting": "0xA9d27E1952A1f26fC7c1d4e4331f2Cc897f8c2d5",
    "RocketDepositPool": "0xDD3f50F8A6CafbE9b31a427582963f465E745AF8",
    "RocketMinipoolQueue": "0x9e966733e3E9BFA56aF95f762921859417cF6FaA",
    "RocketMinipoolManager": "0x6293B8abC1F36aFB22406Be5f96D893072A8cF3a",
    "RocketMinipoolPenalty": "0xE64C0a1D3c3FAE92A2d1B7f57c5C5B7F4B5C8E1D",  # Placeholder
    "RocketDAONodeTrustedUpgrade": "0x9f8E8F9F3F9F3F9F3F9F3F9F3F9F3F9F3F9F3F9F",  # Placeholder
    "RocketDAOSecurity": "0x7E01c9c03FD98049f04Cb6D4b45EE5c6a45b4b4c",  # Placeholder
    "RPL": "0xD33526068D116cE69F19A9ee46F0bd304F21A51f",  # RPL token
}

# Token addresses
TOKEN_ADDRESSES = {
    "RPL": "0xD33526068D116cE69F19A9ee46F0bd304F21A51f",
    "rETH": "0xae78736Cd615f374D3085123A210448E74Fc6393",
}


def get_contract_address(contract_name: str) -> str:
    """Get deployed address for a RocketPool contract."""
    return ROCKETPOOL_ADDRESSES.get(contract_name, "0x0000000000000000000000000000000000000001")


def get_rocketpool_addresses_for_contract(contract_name: str) -> dict:
    """Get all relevant addresses for a specific contract's POC."""
    addresses = {
        "target": get_contract_address(contract_name),
        "rocketStorage": ROCKET_STORAGE,
        "rocketVault": ROCKETPOOL_ADDRESSES["RocketVault"],
        "rpl": TOKEN_ADDRESSES["RPL"],
        "reth": TOKEN_ADDRESSES["rETH"],
    }
    
    # Add specific dependencies based on contract
    if "Auction" in contract_name:
        addresses["rocketNetworkPrices"] = ROCKETPOOL_ADDRESSES["RocketNetworkPrices"]
    
    if "DAO" in contract_name:
        addresses["rocketDAOProposal"] = ROCKETPOOL_ADDRESSES["RocketDAOProposal"]
    
    if "Network" in contract_name:
        addresses["rocketNetworkBalances"] = ROCKETPOOL_ADDRESSES.get("RocketNetworkBalances", addresses["target"])
    
    if "Deposit" in contract_name or "Minipool" in contract_name:
        addresses["rocketDepositPool"] = ROCKETPOOL_ADDRESSES.get("RocketDepositPool", addresses["target"])
    
    return addresses


def generate_address_constants(contract_name: str) -> str:
    """Generate Solidity constants for addresses."""
    addresses = get_rocketpool_addresses_for_contract(contract_name)
    
    lines = []
    lines.append("// RocketPool Mainnet Contract Addresses")
    
    for name, addr in addresses.items():
        const_name = f"{name.upper()}_ADDRESS" if name != "target" else "TARGET_CONTRACT"
        lines.append(f"address constant {const_name} = {addr};")
    
    return '\n'.join(lines)

