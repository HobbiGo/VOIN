const { expect } = require("chai");
const hre = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("VOINPresale & VOINVesting", function () {
  const TREASURY_ADDRESS = "0xAEb22359588A50e6F746004E66418Eb2c978dAA2";
  const PRESALE_START = 1796083200; // 1 Desember 2026 00:00:00 UTC
  const VESTING_DURATION = 365 * 24 * 60 * 60;

  let owner, buyer1, buyer2;
  let mockVoin, vesting, presale;
  let batchPricesUsd;
  let initialBnbPriceUsd;

  beforeEach(async function () {
    [owner, buyer1, buyer2] = await hre.ethers.getSigners();

    // Deploy mock ERC-20 VOIN dengan suplai 260.000.000 VOIN
    const MockERC20 = await hre.ethers.getContractFactory("MockERC20");
    mockVoin = await MockERC20.deploy(
      "VOIN Token",
      "VOIN",
      18,
      hre.ethers.parseUnits("260000000", 18)
    );
    await mockVoin.waitForDeployment();

    const VOINVesting = await hre.ethers.getContractFactory("VOINVesting");
    vesting = await VOINVesting.deploy(
      await mockVoin.getAddress(),
      PRESALE_START,
      VESTING_DURATION
    );
    await vesting.waitForDeployment();

    initialBnbPriceUsd = hre.ethers.parseUnits("600", 18); // $600 / BNB
    batchPricesUsd = [
      "0.01", "0.012", "0.015", "0.018", "0.02",
      "0.024", "0.028", "0.032", "0.036", "0.04",
    ].map((p) => hre.ethers.parseUnits(p, 18));

    const VOINPresale = await hre.ethers.getContractFactory("VOINPresale");
    presale = await VOINPresale.deploy(
      await mockVoin.getAddress(),
      await vesting.getAddress(),
      TREASURY_ADDRESS,
      initialBnbPriceUsd,
      batchPricesUsd
    );
    await presale.waitForDeployment();

    await vesting.setPresaleContract(await presale.getAddress());

    // Transfer 156.000.000 VOIN ke kontrak presale untuk alokasi 10 batch
    await mockVoin.transfer(
      await presale.getAddress(),
      hre.ethers.parseUnits("156000000", 18)
    );
  });

  it("mengonfigurasi 10 batch dan treasury dengan benar", async function () {
    expect(await presale.treasury()).to.equal(TREASURY_ADDRESS);
    expect(await presale.TOTAL_BATCHES()).to.equal(10n);

    const batch1 = await presale.batches(1);
    const batch10 = await presale.batches(10);
    expect(batch1.allocatedVoin).to.equal(hre.ethers.parseUnits("15600000", 18));
    expect(batch10.allocatedVoin).to.equal(hre.ethers.parseUnits("15600000", 18));
  });

  it("menolak pembelian sebelum 1 Desember 2026", async function () {
    await time.increaseTo(PRESALE_START - 60);
    const bnbFor50Usd = hre.ethers.parseEther("50") / 600n;

    await expect(
      presale.connect(buyer1).buyWithBNB({ value: bnbFor50Usd })
    ).to.be.revertedWith("Presale not started yet");
  });

  it("menolak pembelian di bawah $25 dan menerima pembelian valid dalam batas $10.000 per batch", async function () {
    await time.increaseTo(PRESALE_START + 10);

    // Pembelian $20 (gagal karena di bawah minimum $25)
    const bnbFor20Usd = hre.ethers.parseEther("20") / 600n;
    await expect(
      presale.connect(buyer1).buyWithBNB({ value: bnbFor20Usd })
    ).to.be.revertedWith("Below $25 minimum purchase");

    // Pembelian $100 (berhasil dan tercatat di vesting)
    const bnbFor100Usd = hre.ethers.parseEther("100") / 600n;
    await expect(presale.connect(buyer1).buyWithBNB({ value: bnbFor100Usd })).to.emit(
      presale,
      "TokensPurchased"
    );

    const schedule = await vesting.schedules(buyer1.address);
    expect(schedule.totalAllocated).to.be.gt(0n);

    // Pembelian tambahan $9.950 pada batch yang sama -> total $10.050 (melebihi batas $10.000)
    const bnbFor9950Usd = hre.ethers.parseEther("9950") / 600n;
    await expect(
      presale.connect(buyer1).buyWithBNB({ value: bnbFor9950Usd })
    ).to.be.revertedWith("Exceeds $10,000 max per wallet per batch");
  });
});
