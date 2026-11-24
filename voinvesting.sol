// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVoinToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VoinVesting {
    struct VestingSchedule {
        uint256 totalAllocated;
        uint256 claimed;
    }

    IVoinToken public immutable token;
    address public owner;
    mapping(address => bool) public allocators;

    uint256 public vestingStart;
    uint256 public vestingDuration;

    mapping(address => VestingSchedule) public schedules;
    mapping(address => mapping(uint256 => uint256)) public batchAllocationByWallet;

    event AllocationAdded(address indexed beneficiary, uint256 indexed batchId, uint256 amount, uint256 newTotal);
    event TokensClaimed(address indexed beneficiary, uint256 amount);
    event AllocatorUpdated(address indexed allocator, bool allowed);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "VoinVesting: not owner");
        _;
    }

    modifier onlyAllocator() {
        require(msg.sender == owner || allocators[msg.sender], "VoinVesting: not allocator");
        _;
    }

    constructor(
        address tokenAddress,
        uint256 startTimestamp,
        uint256 durationSeconds
    ) {
        require(tokenAddress != address(0), "VoinVesting: zero token");
        require(durationSeconds > 0, "VoinVesting: zero duration");
        token = IVoinToken(tokenAddress);
        owner = msg.sender;
        allocators[msg.sender] = true;
        vestingStart = startTimestamp;
        vestingDuration = durationSeconds;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "VoinVesting: zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setAllocator(address allocator, bool allowed) external onlyOwner {
        require(allocator != address(0), "VoinVesting: zero allocator");
        allocators[allocator] = allowed;
        emit AllocatorUpdated(allocator, allowed);
    }

    function addAllocation(
        address beneficiary,
        uint256 batchId,
        uint256 amount
    ) external onlyAllocator {
        require(beneficiary != address(0), "VoinVesting: zero beneficiary");
        require(amount > 0, "VoinVesting: zero amount");

        VestingSchedule storage sch = schedules[beneficiary];
        sch.totalAllocated += amount;
        batchAllocationByWallet[beneficiary][batchId] += amount;

        emit AllocationAdded(beneficiary, batchId, amount, sch.totalAllocated);
    }

    function vestedAmount(address beneficiary) public view returns (uint256) {
        VestingSchedule memory sch = schedules[beneficiary];
        if (sch.totalAllocated == 0) return 0;
        if (block.timestamp <= vestingStart) return 0;
        if (block.timestamp >= vestingStart + vestingDuration) {
            return sch.totalAllocated;
        }
        uint256 elapsed = block.timestamp - vestingStart;
        return (sch.totalAllocated * elapsed) / vestingDuration;
    }

    function releasableAmount(address beneficiary) public view returns (uint256) {
        uint256 vested = vestedAmount(beneficiary);
        uint256 alreadyClaimed = schedules[beneficiary].claimed;
        if (vested <= alreadyClaimed) return 0;
        return vested - alreadyClaimed;
    }

    function claim() external {
        uint256 amountToClaim = releasableAmount(msg.sender);
        require(amountToClaim > 0, "VoinVesting: nothing to claim");
        require(token.balanceOf(address(this)) >= amountToClaim, "VoinVesting: insufficient token balance");

        schedules[msg.sender].claimed += amountToClaim;
        require(token.transfer(msg.sender, amountToClaim), "VoinVesting: transfer failed");

        emit TokensClaimed(msg.sender, amountToClaim);
    }
}
