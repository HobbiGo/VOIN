// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Payment {
    function decimals() external view returns (uint8);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IVoinVestingTarget {
    function addAllocation(address beneficiary, uint256 batchId, uint256 amount) external;
}

contract VoinPresale {
    struct BatchInfo {
        uint256 voinPriceUsd;   // Skala 1e18 USD per 1 VOIN (misal 0.01 USD = 1e16)
        uint256 allocatedVoin;  // Skala 1e18 VOIN (15,600,000 * 1e18)
        uint256 soldVoin;       // Skala 1e18 VOIN
        bool active;
    }

    uint256 public constant TOTAL_BATCHES = 10;
    uint256 public constant BATCH_ALLOCATION_VOIN = 15_600_000 * 1e18;
    uint256 public constant MIN_PURCHASE_USD = 25 * 1e18;
    uint256 public constant MAX_PURCHASE_USD_PER_WALLET_PER_BATCH = 10_000 * 1e18;

    // 1 Dec 2026 00:00:00 UTC s/d 31 Dec 2028 23:59:59 UTC
    uint256 public constant PRESALE_START = 1796083200;
    uint256 public constant PRESALE_END = 1861919999;

    address public owner;
    address public treasury;
    address public vestingContract;
    bool public paused;

    // Harga BNB dalam USD skala 1e18 (contoh: $600 = 600 * 1e18)
    uint256 public bnbPriceUsd;
    uint256 public currentBatch;

    mapping(uint256 => BatchInfo) public batches;
    mapping(address => bool) public acceptedPaymentTokens;
    mapping(uint256 => mapping(address => uint256)) public walletSpentInBatchUsd;
    mapping(address => uint256) public totalPurchasedVoinByWallet;

    event TokensPurchased(
        address indexed buyer,
        address indexed paymentToken,
        uint256 amountPaidRaw,
        uint256 usdValue,
        uint256 voinAmount,
        uint256 indexed batchId,
        uint256 timestamp
    );
    event PausedUpdated(bool paused);
    event BnbPriceUpdated(uint256 newPriceUsd);
    event PaymentTokenUpdated(address indexed token, bool allowed);
    event BatchActivated(uint256 indexed batchId, bool active);

    modifier onlyOwner() {
        require(msg.sender == owner, "VoinPresale: not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "VoinPresale: paused");
        _;
    }

    constructor(
        address treasuryAddress,
        address vestingAddress,
        uint256 initialBnbPriceUsd
    ) {
        require(treasuryAddress != address(0), "VoinPresale: zero treasury");
        require(vestingAddress != address(0), "VoinPresale: zero vesting");
        require(initialBnbPriceUsd > 0, "VoinPresale: zero BNB price");

        owner = msg.sender;
        treasury = treasuryAddress;
        vestingContract = vestingAddress;
        bnbPriceUsd = initialBnbPriceUsd;
        currentBatch = 1;

        // Inisialisasi 10 batch: masing-masing 15,600,000 VOIN (total 156,000,000 VOIN)
        // Batch 1 = $0.01 (1e16), Batch 2 = $0.02 (2e16), ..., Batch 10 = $0.10 (10e16)
        for (uint256 i = 1; i <= TOTAL_BATCHES; i++) {
            batches[i] = BatchInfo({
                voinPriceUsd: i * 1e16,
                allocatedVoin: BATCH_ALLOCATION_VOIN,
                soldVoin: 0,
                active: (i == 1)
            });
        }
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit PausedUpdated(_paused);
    }

    function setBnbPriceUsd(uint256 newPriceUsd) external onlyOwner {
        require(newPriceUsd > 0, "VoinPresale: zero price");
        bnbPriceUsd = newPriceUsd;
        emit BnbPriceUpdated(newPriceUsd);
    }

    function setPaymentToken(address tokenAddr, bool allowed) external onlyOwner {
        require(tokenAddr != address(0), "VoinPresale: zero token");
        acceptedPaymentTokens[tokenAddr] = allowed;
        emit PaymentTokenUpdated(tokenAddr, allowed);
    }

    function setBatchActive(uint256 batchId, bool active) external onlyOwner {
        require(batchId >= 1 && batchId <= TOTAL_BATCHES, "VoinPresale: invalid batch");
        batches[batchId].active = active;
        if (active) {
            currentBatch = batchId;
        }
        emit BatchActivated(batchId, active);
    }

    function getRemainingBatchVoin(uint256 batchId) public view returns (uint256) {
        if (batchId < 1 || batchId > TOTAL_BATCHES) return 0;
        BatchInfo memory b = batches[batchId];
        if (b.soldVoin >= b.allocatedVoin) return 0;
        return b.allocatedVoin - b.soldVoin;
    }

    function getRemainingWalletQuotaUsd(address wallet, uint256 batchId) public view returns (uint256) {
        uint256 spent = walletSpentInBatchUsd[batchId][wallet];
        if (spent >= MAX_PURCHASE_USD_PER_WALLET_PER_BATCH) return 0;
        return MAX_PURCHASE_USD_PER_WALLET_PER_BATCH - spent;
    }

    function buyWithBNB() external payable whenNotPaused {
        require(msg.value > 0, "VoinPresale: zero BNB");
        uint256 usdValue = (msg.value * bnbPriceUsd) / 1e18;

        (bool ok, ) = payable(treasury).call{value: msg.value}("");
        require(ok, "VoinPresale: BNB transfer failed");

        _processPurchase(msg.sender, address(0), msg.value, usdValue);
    }

    function buyWithToken(address tokenAddress, uint256 tokenAmount) external whenNotPaused {
        require(acceptedPaymentTokens[tokenAddress], "VoinPresale: token not accepted");
        require(tokenAmount > 0, "VoinPresale: zero amount");

        uint8 dec = IERC20Payment(tokenAddress).decimals();
        require(dec <= 36, "VoinPresale: invalid decimals");
        uint256 usdValue = (tokenAmount * 1e18) / (10 ** dec);

        require(IERC20Payment(tokenAddress).transferFrom(msg.sender, treasury, tokenAmount), "VoinPresale: transferFrom failed");

        _processPurchase(msg.sender, tokenAddress, tokenAmount, usdValue);
    }

    function _processPurchase(
        address buyer,
        address paymentToken,
        uint256 amountPaidRaw,
        uint256 usdValue
    ) internal {
        require(block.timestamp >= PRESALE_START && block.timestamp <= PRESALE_END, "VoinPresale: outside presale schedule");
        require(usdValue >= MIN_PURCHASE_USD, "VoinPresale: below $25 minimum");

        uint256 batchId = currentBatch;
        require(batchId >= 1 && batchId <= TOTAL_BATCHES, "VoinPresale: all batches ended");

        BatchInfo storage b = batches[batchId];
        require(b.active, "VoinPresale: batch inactive");

        uint256 newSpentUsd = walletSpentInBatchUsd[batchId][buyer] + usdValue;
        require(newSpentUsd <= MAX_PURCHASE_USD_PER_WALLET_PER_BATCH, "VoinPresale: exceeds $10,000 batch limit");

        uint256 voinAmount = (usdValue * 1e18) / b.voinPriceUsd;
        require(voinAmount > 0, "VoinPresale: zero VOIN");
        require(b.soldVoin + voinAmount <= b.allocatedVoin, "VoinPresale: batch quota exceeded");

        walletSpentInBatchUsd[batchId][buyer] = newSpentUsd;
        b.soldVoin += voinAmount;
        totalPurchasedVoinByWallet[buyer] += voinAmount;

        // Jika kuota batch saat ini penuh dan masih ada batch berikutnya, pindah otomatis ke batch berikutnya
        if (b.soldVoin == b.allocatedVoin && batchId < TOTAL_BATCHES) {
            b.active = false;
            currentBatch = batchId + 1;
            batches[currentBatch].active = true;
        }

        // Catat alokasi ke kontrak vesting agar bisa diklaim sesuai jadwal vesting
        IVoinVestingTarget(vestingContract).addAllocation(buyer, batchId, voinAmount);

        emit TokensPurchased(
            buyer,
            paymentToken,
            amountPaidRaw,
            usdValue,
            voinAmount,
            batchId,
            block.timestamp
        );
    }
}
