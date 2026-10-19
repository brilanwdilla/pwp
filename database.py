"""Fungsi untuk membaca pengaturan dan membuat koneksi ke database."""

import os
import mysql.connector
from dotenv import load_dotenv

# Muat variabel konfigurasi dari .env agar dapat dibaca melalui os.getenv().
load_dotenv()


def get_db_connection():
    """Membuka koneksi MySQL menggunakan nilai dari file .env.

    Nilai setelah koma adalah nilai cadangan yang dipakai jika pengaturan
    tersebut tidak ditemukan di file .env.
    """
    return mysql.connector.connect(
        # Pengaturan koneksi dibaca dari .env; localhost/root adalah nilai bawaan.
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        # Password sebaiknya ditentukan sendiri dalam MYSQL_PASSWORD di .env.
        password=os.getenv("MYSQL_PASSWORD", ""),
        # Jika tidak diatur, aplikasi mencoba memakai database bawaan ini.
        database=os.getenv(
            "MYSQL_DATABASE",
            "db_perpustakaan"
        )
    )
