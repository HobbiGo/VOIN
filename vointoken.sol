// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoinToken {
    string public constant name = "VOIN";
    string public constant symbol = "VOIN";
    uint8 public constant decimals = 18;

    uint256 public constant MAX_SUPPLY = 260_000_000 * 1e18;

    uint256 public totalSupply;
    address public owner;
    mapping(address => bool) public minters;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event MinterUpdated(address indexed minter, bool allowed);

    modifier onlyOwner() {
        require(msg.sender == owner, "VoinToken: not owner");
        _;
    }

    modifier onlyMinter() {
        require(msg.sender == owner || minters[msg.sender], "VoinToken: not minter");
        _;
    }

    constructor(address initialTreasury) {
        require(initialTreasury != address(0), "VoinToken: zero treasury");
        owner = msg.sender;
        minters[msg.sender] = true;
        emit OwnershipTransferred(address(0), msg.sender);
        emit MinterUpdated(msg.sender, true);

        // Mint seluruh 260,000,000 VOIN ke treasury awal (dapat juga dibagi ke presale/vesting setelah deploy)
        _mint(initialTreasury, MAX_SUPPLY);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "VoinToken: zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setMinter(address minter, bool allowed) external onlyOwner {
        require(minter != address(0), "VoinToken: zero minter");
        minters[minter] = allowed;
        emit MinterUpdated(minter, allowed);
    }

    function mint(address to, uint256 amount) external onlyMinter returns (bool) {
        _mint(to, amount);
        return true;
    }

    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "VoinToken: mint to zero");
        require(totalSupply + amount <= MAX_SUPPLY, "VoinToken: max supply exceeded");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        require(spender != address(0), "VoinToken: zero spender");
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        require(currentAllowance >= amount, "VoinToken: insufficient allowance");
        unchecked {
            allowance[from][msg.sender] = currentAllowance - amount;
        }
        emit Approval(from, msg.sender, allowance[from][msg.sender]);
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0) && to != address(0), "VoinToken: zero address");
        require(balanceOf[from] >= amount, "VoinToken: insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
