const hre = require("hardhat");
const { VOIN_PRESALE_CONFIG } = require("../contract_config");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const networkName = hre.network.name;
  const netCfg =
    networkName === "bscMainnet"
      ? VOIN_PRESALE_CONFIG.networks.bscMainnet
      : VOIN_PRESALE_CONFIG.networks.bscTestnet;

  // Isi dengan alamat token VOIN ERC-20 yang sudah di-deploy sebelum menjalankan skrip ini
  const voinTokenAddress = process.env.VOIN_TOKEN_ADDRESS || netCfg.contracts.voinToken;
  if (!voinTokenAddress) {
    throw new Error("VOIN_TOKEN_ADDRESS belum diisi di environment atau contract_config.js");
  }

  const treasuryAddress = process.env.TREASURY_ADDRESS || VOIN_PRESALE_CONFIG.treasuryAddress;

  // Contoh harga awal BNB dalam USD (skala 1e18), misal $600 = 600 * 10^18
  const initialBnbPriceUsd = hre.ethers.parseUnits(process.env.INITIAL_BNB_PRICE_USD || "600", 18);

  // Contoh harga 10 batch dalam USD (skala 1e18), sesuaikan kebutuhan final presale
  const defaultBatchPrices = [
    "0.01", "0.012", "0.015", "0.018", "0.02",
    "0.024", "0.028", "0.032", "0.036", "0.04",
  ];
  const batchPricesUsd = defaultBatchPrices.map((p) => hre.ethers.parseUnits(p, 18));

  // Jadwal vesting: mulai 1 Desember 2026 00:00:00 UTC, durasi 365 hari
  const vestingStart = VOIN_PRESALE_CONFIG.schedule.startTimestampUtc;
  const vestingDuration = Number(process.env.VESTING_DURATION_SECONDS || 365 * 24 * 60 * 60);

  // 1. Deploy VOINVesting
  const VOINVesting = await hre.ethers.getContractFactory("VOINVesting");
  const vesting = await VOINVesting.deploy(voinTokenAddress, vestingStart, vestingDuration);
  await vesting.waitForDeployment();
  const vestingAddress = await vesting.getAddress();
  console.log("VOINVesting deployed to:", vestingAddress);

  // 2. Deploy VOINPresale
  const VOINPresale = await hre.ethers.getContractFactory("VOINPresale");
  const presale = await VOINPresale.deploy(
    voinTokenAddress,
    vestingAddress,
    treasuryAddress,
    initialBnbPriceUsd,
    batchPricesUsd
  );
  await presale.waitForDeployment();
  const presaleAddress = await presale.getAddress();
  console.log("VOINPresale deployed to:", presaleAddress);

  // 3. Hubungkan presaleContract ke VOINVesting
  const setPresaleTx = await vesting.setPresaleContract(presaleAddress);
  await setPresaleTx.wait();
  console.log("Vesting presaleContract set to:", presaleAddress);

  // 4. Konfigurasi USDT & USDC jika alamat tersedia
  const usdtAddress = process.env.USDT_TOKEN_ADDRESS || netCfg.paymentTokens.USDT.address;
  if (usdtAddress) {
    const txUsdt = await presale.configurePaymentToken(
      usdtAddress,
      true,
      netCfg.paymentTokens.USDT.decimals,
      hre.ethers.parseUnits("1", 18)
    );
    await txUsdt.wait();
    console.log("Configured USDT:", usdtAddress);
  }

  const usdcAddress = process.env.USDC_TOKEN_ADDRESS || netCfg.paymentTokens.USDC.address;
  if (usdcAddress) {
    const txUsdc = await presale.configurePaymentToken(
      usdcAddress,
      true,
      netCfg.paymentTokens.USDC.decimals,
      hre.ethers.parseUnits("1", 18)
    );
    await txUsdc.wait();
    console.log("Configured USDC:", usdcAddress);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
