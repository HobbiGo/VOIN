# presale_contract.py
import time
from datetime import datetime

class VOINPresaleContract:
    def __init__(self, state):
        self.state = state
        self.total_supply = 260000000
        self.presale_allocation = 156000000  # 60%
        
        # Pengaturan Batch
        self.total_batches = 10
        self.tokens_per_batch = 15600000     # 10% dari 156 Juta
        self.current_batch = 1
        
        # Waktu (Simulasi Des 2026 - Des 2028)
        # Catatan: Untuk testing, Anda bisa ubah timestamp ini ke waktu sekarang
        self.start_date = datetime(2026, 12, 1).timestamp()
        self.end_date = datetime(2028, 12, 31).timestamp()
        
        # Harga per batch bisa dinaikkan (Opsional)
        # Contoh: Batch 1 lebih murah, Batch 10 lebih mahal
        self.voin_per_unit = 10000 

    def get_current_time(self):
        return time.time()

    def buy_tokens(self, buyer_address, amount_paid):
        current_time = self.get_current_time()
        
        # 1. Cek apakah presale sudah dimulai atau belum
        if current_time < self.start_date:
            return {"status": "failed", "reason": "Presale belum dimulai (Mulai Desember 2026)."}
            
        # 2. Cek apakah presale sudah berakhir
        if current_time > self.end_date:
            return {"status": "failed", "reason": "Presale telah berakhir (Desember 2028)."}

        # 3. Hitung koin yang didapat
        tokens_to_receive = amount_paid * self.voin_per_unit
        
        # 4. Cek kuota batch saat ini
        # (Logika sederhana: Jika batch 1 habis, pindah ke batch 2, dst)
        batch_sold = self.state.get_batch_sold(self.current_batch)
        
        if batch_sold + tokens_to_receive > self.tokens_per_batch:
            # Jika sisa kuota di batch ini tidak cukup, coba pindah ke batch berikutnya
            if self.current_batch < self.total_batches:
                self.current_batch += 1
                self.state.set_current_batch(self.current_batch)
                return {"status": "failed", "reason": f"Batch {self.current_batch-1} habis! Silakan coba lagi untuk masuk ke Batch {self.current_batch}."}
            else:
                return {"status": "failed", "reason": "Semua batch presale (10 Batch) telah habis!"}

        # 5. Eksekusi Transaksi
        self.state.add_balance(buyer_address, tokens_to_receive)
        self.state.update_batch_sold(self.current_batch, tokens_to_receive)
        self.state.save_presale_history(buyer_address, amount_paid, tokens_to_receive, self.current_batch)
        
        return {
            "status": "success", 
            "message": f"Berhasil membeli {tokens_to_receive:,.0f} VOIN di Batch {self.current_batch}"
        }
