import datetime

class VOINPresaleContract:
    """
    Smart Contract VOIN Tiered Presale.
    Mengatur penjualan 130.000.000 VOIN dalam 10 Batch.
    """
    def __init__(self):
        self.contract_name = "VOIN_Presale_V1"
        self.total_presale_allocation = 130_000_000
        self.total_batches = 10
        self.tokens_per_batch = self.total_presale_allocation // self.total_batches # 13.000.000 per batch
        
        # Tanggal mulai presale
        self.start_date = datetime.datetime(2026, 11, 20)
        
        # Konfigurasi Harga per Batch (Mulai $0.001 naik sampai $0.1)
        # Karena kenaikannya eksponensial, kita bisa menetapkan nilai pastinya:
        self.batch_prices = {
            1: 0.001,
            2: 0.002,
            3: 0.004,
            4: 0.008,
            5: 0.015,
            6: 0.025,
            7: 0.040,
            8: 0.060,
            9: 0.080,
            10: 0.100
        }
        
        # State kontrak
        self.current_batch = 1
        self.tokens_sold_current_batch = 0
        self.total_tokens_sold = 0
        self.investors = {}

    def get_current_price(self):
        """Mengembalikan harga VOIN saat ini berdasarkan batch aktif."""
        return self.batch_prices.get(self.current_batch, 0)

    def buy_tokens(self, investor_address, usd_amount):
        """Fungsi yang dipanggil saat investor membeli VOIN."""
        if self.current_batch > self.total_batches:
            return {"success": False, "msg": "Presale has ended. All batches sold out."}

        price = self.get_current_price()
        tokens_to_receive = usd_amount / price

        # Cek apakah pembelian melebihi kuota batch ini
        remaining_in_batch = self.tokens_per_batch - self.tokens_sold_current_batch
        
        if tokens_to_receive > remaining_in_batch:
            # Jika melebihi, potong sesuai sisa kuota batch, sisa uang dikembalikan (refund)
            tokens_to_receive = remaining_in_batch
            actual_usd_spent = tokens_to_receive * price
            refund = usd_amount - actual_usd_spent
        else:
            actual_usd_spent = usd_amount
            refund = 0

        # Update State
        self.tokens_sold_current_batch += tokens_to_receive
        self.total_tokens_sold += tokens_to_receive
        self.investors[investor_address] = self.investors.get(investor_address, 0) + tokens_to_receive

        # Cek jika batch ini habis, pindah ke batch berikutnya
        if self.tokens_sold_current_batch >= self.tokens_per_batch:
            self.current_batch += 1
            self.tokens_sold_current_batch = 0

        return {
            "success": True,
            "tokens_bought": tokens_to_receive,
            "usd_spent": actual_usd_spent,
            "refund": refund,
            "current_batch": self.current_batch,
            "next_price": self.get_current_price()
        }
