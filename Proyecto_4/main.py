from PyQt6.QtWidgets import QApplication
from crypto_Ui import CryptoApp
import sys

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec())
