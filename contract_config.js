const VOIN_PRESALE_CONFIG = {
  treasuryAddress: "0xAEb22359588A50e6F746004E66418Eb2c978dAA2",
  schedule: {
    startTimestampUtc: 1796083200, // 1 Desember 2026 00:00:00 UTC
    endTimestampUtc: 1861919999,   // 31 Desember 2028 23:59:59 UTC
    startLabel: "1 Desember 2026",
    endLabel: "31 Desember 2028",
  },
  limitsUsd: {
    minPurchaseUsd: 25,
    maxPurchaseUsdPerWalletPerBatch: 10000,
    totalBatches: 10,
    batchVoinAllocation: "15600000",
    totalPresaleVoinAllocation: "156000000",
  },
  networks: {
    bscMainnet: {
      chainId: 56,
      chainIdHex: "0x38",
      name: "BNB Smart Chain",
      rpcUrls: ["https://bsc-dataseed.binance.org/"],
      blockExplorerUrls: ["https://bscscan.com"],
      nativeCurrency: {
        name: "BNB",
        symbol: "BNB",
        decimals: 18,
      },
      contracts: {
        voinToken: "",
        voinPresale: "",
        voinVesting: "",
      },
      paymentTokens: {
        USDT: {
          address: "0x55d398326f99059fF775485246999027B3197955",
          symbol: "USDT",
          decimals: 18,
        },
        USDC: {
          address: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
          symbol: "USDC",
          decimals: 18,
        },
      },
    },
    bscTestnet: {
      chainId: 97,
      chainIdHex: "0x61",
      name: "BNB Smart Chain Testnet",
      rpcUrls: ["https://data-seed-prebsc-1-s1.binance.org:8545/"],
      blockExplorerUrls: ["https://testnet.bscscan.com"],
      nativeCurrency: {
        name: "tBNB",
        symbol: "tBNB",
        decimals: 18,
      },
      contracts: {
        voinToken: "",
        voinPresale: "",
        voinVesting: "",
      },
      paymentTokens: {
        USDT: {
          address: "",
          symbol: "USDT",
          decimals: 18,
        },
        USDC: {
          address: "",
          symbol: "USDC",
          decimals: 18,
        },
      },
    },
  },
  abis: {
    erc20: [
      "function name() view returns (string)",
      "function symbol() view returns (string)",
      "function decimals() view returns (uint8)",
      "function balanceOf(address account) view returns (uint256)",
      "function allowance(address owner, address spender) view returns (uint256)",
      "function approve(address spender, uint256 amount) returns (bool)",
    ],
    voinPresale: [
      "function currentBatch() view returns (uint256)",
      "function bnbPriceUsd() view returns (uint256)",
      "function paused() view returns (bool)",
      "function treasury() view returns (address)",
      "function batches(uint256 batchId) view returns (uint256 voinPriceUsd, uint256 allocatedVoin, uint256 soldVoin, bool active)",
      "function walletSpentInBatchUsd(uint256 batchId, address wallet) view returns (uint256)",
      "function totalPurchasedVoinByWallet(address wallet) view returns (uint256)",
      "function getRemainingBatchVoin(uint256 batchId) view returns (uint256)",
      "function getRemainingWalletQuotaUsd(address wallet, uint256 batchId) view returns (uint256)",
      "function buyWithBNB() payable",
      "function buyWithToken(address tokenAddress, uint256 tokenAmount)",
      "event TokensPurchased(address indexed buyer, address indexed paymentToken, uint256 amountPaidRaw, uint256 usdValue, uint256 voinAmount, uint256 indexed batchId, uint256 timestamp)",
    ],
    voinVesting: [
      "function vestingStart() view returns (uint256)",
      "function vestingDuration() view returns (uint256)",
      "function schedules(address beneficiary) view returns (uint256 totalAllocated, uint256 claimed)",
      "function batchAllocationByWallet(address beneficiary, uint256 batchId) view returns (uint256)",
      "function vestedAmount(address beneficiary) view returns (uint256)",
      "function releasableAmount(address beneficiary) view returns (uint256)",
      "function claim()",
      "event AllocationAdded(address indexed beneficiary, uint256 indexed batchId, uint256 amount, uint256 newTotal)",
      "event TokensClaimed(address indexed beneficiary, uint256 amount)",
    ],
  },
};

if (typeof window !== "undefined") {
  window.VOIN_PRESALE_CONFIG = VOIN_PRESALE_CONFIG;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { VOIN_PRESALE_CONFIG };
}
