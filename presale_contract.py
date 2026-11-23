import time
from datetime import datetime, timezone


class VOINPresaleContract:
    def __init__(self, state):
        self.state = state
        self.total_supply = 260_000_000
        self.presale_allocation = 156_000_000  # 60%

        # Official receiving wallet
        self.receiving_wallet = "0xAEb22359588A50e6F746004E66418Eb2c978dAA2"

        # 10 batches x 15,600,000 VOIN
        self.total_batches = 10
        self.tokens_per_batch = 15_600_000
        self.current_batch = 1

        # Sesuaikan dengan UI dan worker.js
        self.min_purchase_usd = 25.0

        # Locked USD price per 1 VOIN
        self.batch_prices_usd = {
            1: 0.01,
            2: 0.02,
            3: 0.03,
            4: 0.04,
            5: 0.05,
            6: 0.06,
            7: 0.07,
            8: 0.08,
            9: 0.09,
            10: 0.10,
        }

        self.sales_counter = 0

        # Gunakan timezone.utc agar konsisten di server mana pun
        self.start_date = datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp()
        self.end_date = datetime(2028, 12, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp()

    def get_current_time(self):
        return time.time()

    def get_batch_price_usd(self, batch_number=None):
        batch = int(batch_number if batch_number is not None else self.current_batch)
        return float(self.batch_prices_usd.get(batch, batch * 0.01))

    def buy_tokens(self, buyer_address, amount_paid, receiver_wallet=None):
        current_time = self.get_current_time()

        if current_time < self.start_date:
            return {
                "status": "failed",
                "reason": "Presale has not started yet (Starts December 2026).",
            }
        if current_time > self.end_date:
            return {
                "status": "failed",
                "reason": "Presale has ended (December 2028).",
            }

        clean_buyer = str(buyer_address or "").strip()
        if not clean_buyer:
            return {
                "status": "failed",
                "reason": "Wallet address is required.",
            }

        try:
            amount_usd = float(amount_paid)
        except (TypeError, ValueError):
            return {
                "status": "failed",
                "reason": "Invalid payment amount.",
            }

        if amount_usd < self.min_purchase_usd:
            return {
                "status": "failed",
                "reason": f"Minimum purchase is ${self.min_purchase_usd:.0f}.",
            }

        remaining_usd = amount_usd
        total_tokens_received = 0.0
        batches_processed = []

        while remaining_usd > 1e-9 and self.current_batch <= self.total_batches:
            unit_price = self.get_batch_price_usd(self.current_batch)
            batch_sold = float(self.state.get_batch_sold(self.current_batch))
            batch_remaining_voin = max(0.0, float(self.tokens_per_batch) - batch_sold)

            if batch_remaining_voin <= 1e-9:
                self.current_batch += 1
                self.state.set_current_batch(self.current_batch)
                continue

            usd_needed_for_batch = batch_remaining_voin * unit_price

            if remaining_usd >= usd_needed_for_batch - 1e-9:
                tokens_bought = round(batch_remaining_voin, 6)
                spent_usd = usd_needed_for_batch
                remaining_usd = max(0.0, remaining_usd - spent_usd)

                self.state.update_batch_sold(self.current_batch, tokens_bought)
                if self.current_batch not in batches_processed:
                    batches_processed.append(self.current_batch)

                if self.current_batch < self.total_batches:
                    self.current_batch += 1
                    self.state.set_current_batch(self.current_batch)
                else:
                    self.current_batch = self.total_batches + 1
                    self.state.set_current_batch(self.current_batch)
                    break
            else:
                tokens_bought = round(remaining_usd / unit_price, 6)
                remaining_usd = 0.0

                self.state.update_batch_sold(self.current_batch, tokens_bought)
                if self.current_batch not in batches_processed:
                    batches_processed.append(self.current_batch)
                break

            total_tokens_received = round(total_tokens_received + tokens_bought, 6)

        if total_tokens_received <= 0 or not batches_processed:
            return {
                "status": "failed",
                "reason": "All 10 presale batches are sold out!",
            }

        self.sales_counter += 1
        sales_rank = self.sales_counter
        target_receiver = str(receiver_wallet).strip() if receiver_wallet else self.receiving_wallet

        recorded_batch = batches_processed[-1]
        self.state.add_balance(clean_buyer, total_tokens_received)
        self.state.save_presale_history(clean_buyer, amount_usd, total_tokens_received, recorded_batch)

        batch_label = (
            f"Batch {batches_processed[0]}"
            if len(batches_processed) == 1
            else f"Batch {batches_processed[0]} to {batches_processed[-1]}"
        )

        return {
            "status": "success",
            "batch": batch_label,
            "receiver_wallet": target_receiver,
            "tokens_received": total_tokens_received,
            "sales_rank": sales_rank,
            "message": f"Successfully purchased {total_tokens_received:,.2f} VOIN.",
        }
