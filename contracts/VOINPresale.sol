// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

interface IVOINVesting {
    function addAllocation(address beneficiary, uint256 voinAmount, uint256 batchId) external;
}

contract VOINPresale {
    address public owner;
    address public treasury;
    IERC20Minimal public voinToken;
    IVOINVesting public vestingContract;

    // Jadwal presale: 1 Desember 2026 00:00:00 UTC (1796083200) s/d 31 Desember 2028 23:59:59 UTC (1861919999)
    uint256 public constant PRESALE_START = 1796083200;
    uint256 public constant PRESALE_END = 1861919999;

    // Batas pembelian per wallet per batch dalam skala 1e18 USD
    uint256 public constant MIN_PURCHASE_USD = 25 * 1e18;
    uint256 public constant MAX_PURCHASE_USD_PER_BATCH = 10000 * 1e18;

    // 10 batch presale, masing-masing 15.600.000 VOIN (total 156.000.000 VOIN)
    uint256 public constant TOTAL_BATCHES = 10;
    uint256 public constant BATCH_VOIN_ALLOCATION = 15_600_000 * 1e18;

    struct BatchInfo {
        uint256 voinPriceUsd; // Harga 1 VOIN dalam USD skala 1e18 (contoh: 0.05 USD = 5e16)
        uint256 allocatedVoin;
        uint256 soldVoin;
        bool active;
    }

    struct PaymentTokenConfig {
        bool enabled;
        uint8 decimals;
        uint256 usdPricePerToken; // Nilai 1 unit token (setelah normalisasi/desimal) dalam USD skala 1e18
    }

    uint256 public currentBatch = 1;
    uint256 public bnbPriceUsd; // Harga 1 BNB dalam USD skala 1e18 (diperbarui oleh owner/oracle)
    bool public paused;

    mapping(uint256 => BatchInfo) public batches;
    mapping(address => PaymentTokenConfig) public paymentTokens;
    // batchId => wallet => total pembelian USD (skala 1e18) pada batch tersebut
    mapping(uint256 => mapping(address => uint256)) public walletSpentInBatchUsd;
    // wallet => total VOIN yang dibeli
    mapping(address => uint256) public totalPurchasedVoinByWallet;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event VestingContractUpdated(address indexed oldVesting, address indexed newVesting);
    event BnbPriceUpdated(uint256 newPriceUsd);
    event BatchConfigured(uint256 indexed batchId, uint256 voinPriceUsd, uint256 allocatedVoin, bool active);
    event CurrentBatchChanged(uint256 indexed newBatchId);
    event PaymentTokenConfigured(address indexed token, bool enabled, uint8 decimals, uint256 usdPricePerToken);
    event TokensPurchased(
        address indexed buyer,
        address indexed paymentToken, // address(0) untuk BNB native
        uint256 amountPaidRaw,
        uint256 usdValue,
        uint256 voinAmount,
        uint256 indexed batchId,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Presale paused");
        _;
    }

    modifier presaleActiveWindow() {
        require(block.timestamp >= PRESALE_START, "Presale not started yet");
        require(block.timestamp <= PRESALE_END, "Presale period ended");
        _;
    }

    constructor(
        address _voinToken,
        address _vestingContract,
        address _treasury,
        uint256 _bnbPriceUsd,
        uint256[] memory _batchPricesUsd
    ) {
        require(_treasury != address(0), "Invalid treasury");
        require(_voinToken != address(0), "Invalid VOIN token");
        require(_batchPricesUsd.length == TOTAL_BATCHES, "Must set 10 batch prices");
        require(_bnbPriceUsd > 0, "Invalid BNB price");

        owner = msg.sender;
        treasury = _treasury;
        voinToken = IERC20Minimal(_voinToken);
        vestingContract = IVOINVesting(_vestingContract);
        bnbPriceUsd = _bnbPriceUsd;

        for (uint256 i = 0; i < TOTAL_BATCHES; i++) {
            uint256 bId = i + 1;
            require(_batchPricesUsd[i] > 0, "Invalid batch price");
            batches[bId] = BatchInfo({
                voinPriceUsd: _batchPricesUsd[i],
                allocatedVoin: BATCH_VOIN_ALLOCATION,
                soldVoin: 0,
                active: (bId == 1)
            });
            emit BatchConfigured(bId, _batchPricesUsd[i], BATCH_VOIN_ALLOCATION, bId == 1);
        }
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "Zero address");
        emit TreasuryUpdated(treasury, newTreasury);
        treasury = newTreasury;
    }

    function setVestingContract(address newVesting) external onlyOwner {
        emit VestingContractUpdated(address(vestingContract), newVesting);
        vestingContract = IVOINVesting(newVesting);
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
    }

    function setBnbPriceUsd(uint256 _bnbPriceUsd) external onlyOwner {
        require(_bnbPriceUsd > 0, "Invalid BNB price");
        bnbPriceUsd = _bnbPriceUsd;
        emit BnbPriceUpdated(_bnbPriceUsd);
    }

    function setCurrentBatch(uint256 newBatchId) external onlyOwner {
        require(newBatchId >= 1 && newBatchId <= TOTAL_BATCHES, "Invalid batch ID");
        batches[currentBatch].active = false;
        currentBatch = newBatchId;
        batches[newBatchId].active = true;
        emit CurrentBatchChanged(newBatchId);
    }

    function configureBatch(uint256 batchId, uint256 voinPriceUsd, bool active) external onlyOwner {
        require(batchId >= 1 && batchId <= TOTAL_BATCHES, "Invalid batch ID");
        require(voinPriceUsd > 0, "Invalid price");
        batches[batchId].voinPriceUsd = voinPriceUsd;
        batches[batchId].active = active;
        emit BatchConfigured(batchId, voinPriceUsd, batches[batchId].allocatedVoin, active);
    }

    function configurePaymentToken(
        address tokenAddress,
        bool enabled,
        uint8 decimals,
        uint256 usdPricePerToken
    ) external onlyOwner {
        require(tokenAddress != address(0), "Use buyWithBNB for native BNB");
        require(!enabled || usdPricePerToken > 0, "Invalid USD price");
        paymentTokens[tokenAddress] = PaymentTokenConfig({
            enabled: enabled,
            decimals: decimals,
            usdPricePerToken: usdPricePerToken
        });
        emit PaymentTokenConfigured(tokenAddress, enabled, decimals, usdPricePerToken);
    }

    function getRemainingBatchVoin(uint256 batchId) external view returns (uint256) {
        BatchInfo memory b = batches[batchId];
        if (b.soldVoin >= b.allocatedVoin) return 0;
        return b.allocatedVoin - b.soldVoin;
    }

    function getRemainingWalletQuotaUsd(address wallet, uint256 batchId) external view returns (uint256) {
        uint256 spent = walletSpentInBatchUsd[batchId][wallet];
        if (spent >= MAX_PURCHASE_USD_PER_BATCH) return 0;
        return MAX_PURCHASE_USD_PER_BATCH - spent;
    }

    function buyWithBNB() external payable whenNotPaused presaleActiveWindow {
        require(msg.value > 0, "Zero BNB sent");
        require(bnbPriceUsd > 0, "BNB price not set");

        // msg.value berdesimal 18, bnbPriceUsd berdesimal 18 -> hasil USD berdesimal 18
        uint256 usdValue = (msg.value * bnbPriceUsd) / 1e18;
        _processPurchase(msg.sender, address(0), msg.value, usdValue);

        (bool ok, ) = payable(treasury).call{value: msg.value}("");
        require(ok, "Treasury BNB transfer failed");
    }

    function buyWithToken(address tokenAddress, uint256 tokenAmount) external whenNotPaused presaleActiveWindow {
        PaymentTokenConfig memory cfg = paymentTokens[tokenAddress];
        require(cfg.enabled, "Payment token not supported");
        require(tokenAmount > 0, "Zero token amount");

        uint256 normalizedAmount = tokenAmount * (10 ** (18 - cfg.decimals));
        uint256 usdValue = (normalizedAmount * cfg.usdPricePerToken) / 1e18;

        _processPurchase(msg.sender, tokenAddress, tokenAmount, usdValue);

        bool ok = IERC20Minimal(tokenAddress).transferFrom(msg.sender, treasury, tokenAmount);
        require(ok, "Treasury token transfer failed");
    }

    function _processPurchase(
        address buyer,
        address paymentToken,
        uint256 amountPaidRaw,
        uint256 usdValue
    ) internal {
        require(usdValue >= MIN_PURCHASE_USD, "Below $25 minimum purchase");

        BatchInfo storage batch = batches[currentBatch];
        require(batch.active, "Current batch is not active");

        uint256 newWalletBatchTotal = walletSpentInBatchUsd[currentBatch][buyer] + usdValue;
        require(
            newWalletBatchTotal <= MAX_PURCHASE_USD_PER_BATCH,
            "Exceeds $10,000 max per wallet per batch"
        );

        // voinAmount berdesimal 18: (usdValue * 1e18) / voinPriceUsd
        uint256 voinAmount = (usdValue * 1e18) / batch.voinPriceUsd;
        require(voinAmount > 0, "VOIN amount too small");
        require(batch.soldVoin + voinAmount <= batch.allocatedVoin, "Exceeds batch VOIN supply");

        walletSpentInBatchUsd[currentBatch][buyer] = newWalletBatchTotal;
        batch.soldVoin += voinAmount;
        totalPurchasedVoinByWallet[buyer] += voinAmount;

        if (address(vestingContract) != address(0)) {
            bool sentToVesting = voinToken.transfer(address(vestingContract), voinAmount);
            require(sentToVesting, "VOIN transfer to vesting failed");
            vestingContract.addAllocation(buyer, voinAmount, currentBatch);
        } else {
            bool sentToBuyer = voinToken.transfer(buyer, voinAmount);
            require(sentToBuyer, "VOIN transfer to buyer failed");
        }

        emit TokensPurchased(
            buyer,
            paymentToken,
            amountPaidRaw,
            usdValue,
            voinAmount,
            currentBatch,
            block.timestamp
        );
    }

    receive() external payable {
        revert("Use buyWithBNB");
    }
}
