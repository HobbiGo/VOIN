// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Vesting {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VOINVesting {
    address public owner;
    address public presaleContract;
    IERC20Vesting public immutable voinToken;

    // Mulai vesting selaras dengan jadwal presale (1 Desember 2026 00:00:00 UTC)
    uint256 public immutable vestingStart;
    // Durasi vesting linier (contoh: 365 hari setelah vestingStart)
    uint256 public immutable vestingDuration;

    struct VestingSchedule {
        uint256 totalAllocated;
        uint256 claimed;
    }

    mapping(address => VestingSchedule) public schedules;
    mapping(address => mapping(uint256 => uint256)) public batchAllocationByWallet;

    event AllocationAdded(address indexed beneficiary, uint256 indexed batchId, uint256 amount, uint256 newTotal);
    event TokensClaimed(address indexed beneficiary, uint256 amount);
    event PresaleContractUpdated(address indexed oldPresale, address indexed newPresale);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyPresaleOrOwner() {
        require(msg.sender == presaleContract || msg.sender == owner, "Not authorized");
        _;
    }

    constructor(
        address _voinToken,
        uint256 _vestingStart,
        uint256 _vestingDuration
    ) {
        require(_voinToken != address(0), "Invalid VOIN token");
        require(_vestingDuration > 0, "Invalid vesting duration");

        owner = msg.sender;
        voinToken = IERC20Vesting(_voinToken);
        vestingStart = _vestingStart;
        vestingDuration = _vestingDuration;
    }

    function setPresaleContract(address _presaleContract) external onlyOwner {
        require(_presaleContract != address(0), "Zero address");
        emit PresaleContractUpdated(presaleContract, _presaleContract);
        presaleContract = _presaleContract;
    }

    function addAllocation(address beneficiary, uint256 voinAmount, uint256 batchId) external onlyPresaleOrOwner {
        require(beneficiary != address(0), "Invalid beneficiary");
        require(voinAmount > 0, "Zero amount");

        VestingSchedule storage s = schedules[beneficiary];
        s.totalAllocated += voinAmount;
        batchAllocationByWallet[beneficiary][batchId] += voinAmount;

        emit AllocationAdded(beneficiary, batchId, voinAmount, s.totalAllocated);
    }

    function vestedAmount(address beneficiary) public view returns (uint256) {
        VestingSchedule memory s = schedules[beneficiary];
        if (s.totalAllocated == 0 || block.timestamp < vestingStart) {
            return 0;
        }
        if (block.timestamp >= vestingStart + vestingDuration) {
            return s.totalAllocated;
        }
        uint256 elapsed = block.timestamp - vestingStart;
        return (s.totalAllocated * elapsed) / vestingDuration;
    }

    function releasableAmount(address beneficiary) public view returns (uint256) {
        uint256 vested = vestedAmount(beneficiary);
        uint256 alreadyClaimed = schedules[beneficiary].claimed;
        if (vested <= alreadyClaimed) return 0;
        return vested - alreadyClaimed;
    }

    function claim() external {
        uint256 amountToClaim = releasableAmount(msg.sender);
        require(amountToClaim > 0, "Nothing to claim");

        schedules[msg.sender].claimed += amountToClaim;
        bool ok = voinToken.transfer(msg.sender, amountToClaim);
        require(ok, "Token transfer failed");

        emit TokensClaimed(msg.sender, amountToClaim);
    }
}
