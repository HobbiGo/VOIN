import datetime

class VOINPresaleContract:
    def __init__(self, treasury_address):
        self.contract_name = "VOIN_Presale_V1"
        self.treasury_address = treasury_address # Dompet Developer/Tim
        self.total_presale_allocation = 130_000_000
        self.total_batches = 10
        self.tokens_per_batch = self.total_presale_allocation // self.total_batches
        
        self.batch_prices = {
            1: 0.001, 2: 0.002, 3: 0.004, 4: 0.008, 5: 0.015,
            6: 0.025, 7: 0.040, 8: 0.060, 9: 0.080, 10: 0.100
        }
        
        self.current_batch = 1
        self.tokens_sold_current_batch = 0
        self.total_tokens_sold = 0
        self.investors = {} # Mencatat alamat pembeli -> jumlah VOIN

    def execute(self, sender_address, usd_amount):
        """Fungsi utama yang dipanggil saat investor membeli."""
        if self.current_batch > self.total_batches:
            raise Exception("Presale has ended.")

        price = self.batch_prices[self.current_batch]
        tokens_to_receive = usd_amount / price

        remaining_in_batch = self.tokens_per_batch - self.tokens_sold_current_batch
        
        if tokens_to_receive > remaining_in_batch:
            tokens_to_receive = remaining_in_batch
            actual_usd_spent = tokens_to_receive * price
            refund = usd_amount - actual_usd_spent
        else:
            actual_usd_spent = usd_amount
            refund = 0

        self.tokens_sold_current_batch += tokens_to_receive
        self.total_tokens_sold += tokens_to_receive
        self.investors[sender_address] = self.investors.get(sender_address, 0) + tokens_to_receive

        if self.tokens_sold_current_batch >= self.tokens_per_batch:
            self.current_batch += 1
            self.tokens_sold_current_batch = 0

        return {
            "status": "success",
            "investor": sender_address,
            "tokens_bought": tokens_to_receive,
            "usd_spent": actual_usd_spent,
            "refund": refund,
            "current_batch": self.current_batch
        }
