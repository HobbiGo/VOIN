# presale_contract.py

class VOINPresaleContract:
    def __init__(self, state):
        self.state = state
        self.total_supply = 260000000
        self.presale_allocation = 156000000  # 60% dari 260 Juta
        self.tokens_sold = 0
        
        # HARGA PRESALE: 
        # Misal 1 USDT/Rupiah (dalam satuan unit) = 10.000 VOIN
        # Silakan sesuaikan rate ini dengan strategi bisnis Anda
        self.voin_per_unit = 10000 

    def buy_tokens(self, buyer_address, amount_paid):
        # 1. Hitung VOIN yang didapat pembeli
        tokens_to_receive = amount_paid * self.voin_per_unit
        
        # 2. Cek apakah kuota presale habis
        if self.tokens_sold + tokens_to_receive > self.presale_allocation:
            return {
                "status": "failed", 
                "reason": "Maaf, alokasi presale 156 Juta VOIN sudah habis!"
            }

        # 3. Proses Pembayaran (Di sini asumsinya amount_paid sudah tervalidasi lunas)
        # 4. Tambahkan saldo VOIN ke dompet pembeli
        self.state.add_balance(buyer_address, tokens_to_receive)
        
        # 5. Catat penjualan
        self.tokens_sold += tokens_to_receive
        self.state.update_presale_sold(self.tokens_sold)
        
        # 6. Simpan riwayat untuk dashboard
        self.state.save_presale_history(buyer_address, amount_paid, tokens_to_receive)
        
        return {
            "status": "success", 
            "message": f"Berhasil membeli {tokens_to_receive:,.0f} VOIN"
        }
