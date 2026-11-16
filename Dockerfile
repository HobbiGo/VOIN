# Gunakan Python versi ringan
FROM python:3.13-slim

# Set working directory di dalam container
WORKDIR /app

# Copy file requirements terlebih dahulu agar caching lebih cepat
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy seluruh sisa kode proyek ke dalam container
COPY . .

# Buka port default (5000)
EXPOSE 5000

# Perintah untuk menjalankan Node VOIN saat container dinyalakan
CMD ["python", "node.py", "5000"]
