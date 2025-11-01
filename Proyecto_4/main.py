# main.py
import sys
from PyQt6.QtWidgets import QApplication
from crypto_Ui import CryptoApp

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CryptoApp()
    win.show()
    sys.exit(app.exec())
