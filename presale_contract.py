import time
from datetime import datetime


class VOINPresaleContract:
    def __init__(self, state):
        self.state = state
        self.total_supply = 260000000
        self.presale_allocation = 156000000  # 60%

        # Pengaturan Batch
        self.total_batches = 10
        self.tokens_per_batch = 15600000     # 15,6 juta VOIN per batch
        self.current_batch = 1

        # Aturan Pembelian: minimal $10, maksimum bebas selama sisa kuota batch mencukupi
        self.min_purchase_usd = 10.0

        # Harga terkunci per batch dalam USD per 1 VOIN
        self.batch_prices_usd = {
            1: 0.01,  # 100.00 VOIN per $1
            2: 0.02,  # 50.00 VOIN per $1
            3: 0.03,  # ~33.33 VOIN per $1
            4: 0.04,  # 25.00 VOIN per $1
            5: 0.05,  # 20.00 VOIN per $1
            6: 0.06,  # ~16.67 VOIN per $1
            7: 0.07,  # ~14.29 VOIN per $1
            8: 0.08,  # 12.50 VOIN per $1
            9: 0.09,  # ~11.11 VOIN per $1
            10: 0.10, # 10.00 VOIN per $1
        }

        # Waktu (Simulasi Des 2026 - Des 2028)
        # Catatan: Untuk testing sebelum Desember 2026, sesuaikan start_date sementara
        self.start_date = datetime(2026, 12, 1).timestamp()
        self.end_date = datetime(2028, 12, 31).timestamp()

    def get_current_time(self):
        return time.time()

    def get_batch_price_usd(self, batch_number=None):
        batch = batch_number if batch_number is not None else self.current_batch
        return float(self.batch_prices_usd.get(batch, batch * 0.01))

    def get_batch_rate_per_usd(self, batch_number=None):
        price = self.get_batch_price_usd(batch_number)
        return 1.0 / price if price > 0 else 0.0

    def buy_tokens(self, buyer_address, amount_paid):
        current_time = self.get_current_time()

        # 1. Cek jadwal presale
        if current_time < self.start_date:
            return {"status": "failed", "reason": "Presale has not started yet (Starts December 2026)."}

        if current_time > self.end_date:
            return {"status": "failed", "reason": "Presale has ended (December 2028)."}

        # 2. Validasi wallet & minimal pembelian $10 (maksimum bebas sesuai kuota batch)
        if not buyer_address or not str(buyer_address).strip():
            return {"status": "failed", "reason": "Wallet address is required."}

        try:
            amount_usd = float(amount_paid)
        except (TypeError, ValueError):
            return {"status": "failed", "reason": "Invalid payment amount."}

        if amount_usd < self.min_purchase_usd:
            return {
                "status": "failed",
                "reason": f"Minimum purchase is ${self.min_purchase_usd:.0f}."
            }

        # 3. Hitung VOIN berdasarkan harga terkunci batch aktif
        unit_price_usd = self.get_batch_price_usd(self.current_batch)
        tokens_to_receive = amount_usd / unit_price_usd

        # 4. Cek kuota batch aktif (15,600,000 VOIN per batch)
        batch_sold = float(self.state.get_batch_sold(self.current_batch))

        if batch_sold + tokens_to_receive > self.tokens_per_batch:
            if self.current_batch < self.total_batches:
                finished_batch = self.current_batch
                self.current_batch += 1
                self.state.set_current_batch(self.current_batch)
                next_price = self.get_batch_price_usd(self.current_batch)
                return {
                    "status": "failed",
                    "reason": (
                        f"Batch {finished_batch} quota reached! Switched to Batch {self.current_batch} "
                        f"(${next_price:.2f} / VOIN). Please resubmit your order."
                    )
                }
            return {"status": "failed", "reason": "All 10 presale batches are sold out!"}

        # 5. Eksekusi transaksi & catat riwayat
        self.state.add_balance(buyer_address, tokens_to_receive)
        self.state.update_batch_sold(self.current_batch, tokens_to_receive)
        self.state.save_presale_history(buyer_address, amount_usd, tokens_to_receive, self.current_batch)

        return {
            "status": "success",
            "batch": self.current_batch,
            "price_per_voin_usd": unit_price_usd,
            "voin_per_usd": round(1.0 / unit_price_usd, 4),
            "tokens_received": tokens_to_receive,
            "message": f"Successfully purchased {tokens_to_receive:,.2f} VOIN in Batch {self.current_batch} at ${unit_price_usd:.2f}/VOIN"
        }
