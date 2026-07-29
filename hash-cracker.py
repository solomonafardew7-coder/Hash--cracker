#!/usr/bin/env python3

import sys
import hashlib
import sqlite3
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTextEdit,
    QComboBox,
    QMessageBox,
    QProgressBar,
)


BASE_DIR = Path(__file__).resolve().parent
WORDLIST_FILE = BASE_DIR / "wordlist.txt"
DATABASE_FILE = BASE_DIR / "database.db"

ALGORITHMS = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
}

HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}


# ============================================================
# HASH
# ============================================================

def make_hash(text, algorithm):
    return hashlib.new(
        algorithm,
        text.encode("utf-8")
    ).hexdigest()


# ============================================================
# DATABASE
# ============================================================

class HashDatabase:

    def __init__(self, filename):

        self.connection = sqlite3.connect(
            filename
        )

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                hash TEXT NOT NULL,
                plaintext TEXT NOT NULL,
                UNIQUE(algorithm, hash)
            )
        """)

        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_hash_lookup
            ON hashes(algorithm, hash)
        """)

        self.connection.commit()


    def add(self, algorithm, digest, plaintext):

        self.connection.execute(
            """
            INSERT OR IGNORE INTO hashes
            (algorithm, hash, plaintext)
            VALUES (?, ?, ?)
            """,
            (
                algorithm,
                digest,
                plaintext
            )
        )


    def search(self, algorithm, digest):

        return self.connection.execute(
            """
            SELECT plaintext
            FROM hashes
            WHERE algorithm = ?
            AND hash = ?
            LIMIT 1
            """,
            (
                algorithm,
                digest
            )
        ).fetchone()


    def count(self):

        return self.connection.execute(
            """
            SELECT COUNT(*)
            FROM hashes
            """
        ).fetchone()[0]


    def clear(self):

        self.connection.execute(
            "DELETE FROM hashes"
        )

        self.connection.commit()


    def commit(self):

        self.connection.commit()


    def close(self):

        self.connection.close()


# ============================================================
# BUILD DATABASE FROM WORDLIST
# ============================================================

def build_database(db, progress_callback=None):

    if not WORDLIST_FILE.exists():

        raise FileNotFoundError(
            f"wordlist.txt not found:\n{WORDLIST_FILE}"
        )


    with open(
        WORDLIST_FILE,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        lines = file.readlines()


    total = len(lines)

    if total == 0:

        raise ValueError(
            "wordlist.txt is empty."
        )


    processed = 0


    for line in lines:

        word = line.rstrip(
            "\r\n"
        )

        # Skip empty lines
        if not word:

            continue


        # Create ALL 3 hashes
        for algorithm in (
            "md5",
            "sha1",
            "sha256"
        ):

            digest = make_hash(
                word,
                algorithm
            )

            db.add(
                algorithm,
                digest,
                word
            )


        processed += 1


        if progress_callback:

            percentage = int(
                processed * 100 / total
            )

            progress_callback(
                percentage
            )


    db.commit()


# ============================================================
# GUI
# ============================================================

class HashCracker(QWidget):

    def __init__(self):

        super().__init__()

        self.db = HashDatabase(
            DATABASE_FILE
        )

        self.setWindowTitle(
            "HASH CRACKER"
        )

        self.setMinimumSize(
            800,
            600
        )

        self.create_gui()

        # Check database status on startup (Only build if empty)
        self.start_database()


    # ========================================================
    # GUI
    # ========================================================

    def create_gui(self):

        main = QVBoxLayout()


        # ----------------------------------------------------
        # TITLE
        # ----------------------------------------------------

        title = QLabel(
            "HASH CRACKER"
        )

        title.setStyleSheet("""
            font-size: 30px;
            font-weight: bold;
            padding: 10px;
        """)

        main.addWidget(
            title
        )


        subtitle = QLabel(
            "Local Wordlist → Hash Database → Lookup"
        )

        subtitle.setStyleSheet(
            "font-size: 14px;"
        )

        main.addWidget(
            subtitle
        )


        # ----------------------------------------------------
        # DATABASE
        # ----------------------------------------------------

        database_label = QLabel(
            "DATABASE"
        )

        database_label.setStyleSheet(
            "font-size: 16px; font-weight: bold;"
        )

        main.addWidget(
            database_label
        )


        self.database_status = QLabel(
            "Starting..."
        )

        main.addWidget(
            self.database_status
        )


        self.progress = QProgressBar()

        self.progress.setValue(
            0
        )

        main.addWidget(
            self.progress
        )


        # ----------------------------------------------------
        # REBUILD BUTTON
        # ----------------------------------------------------

        rebuild = QPushButton(
            "REBUILD DATABASE FROM WORDLIST"
        )

        rebuild.clicked.connect(
            self.rebuild_database
        )

        main.addWidget(
            rebuild
        )


        # ----------------------------------------------------
        # ALGORITHM
        # ----------------------------------------------------

        algorithm_row = QHBoxLayout()


        algorithm_row.addWidget(
            QLabel("Algorithm:")
        )


        self.algorithm_box = QComboBox()

        self.algorithm_box.addItems(
            [
                "MD5",
                "SHA-1",
                "SHA-256"
            ]
        )


        algorithm_row.addWidget(
            self.algorithm_box
        )


        main.addLayout(
            algorithm_row
        )


        # ----------------------------------------------------
        # HASH INPUT
        # ----------------------------------------------------

        main.addWidget(
            QLabel("Hash:")
        )


        self.hash_input = QLineEdit()

        self.hash_input.setPlaceholderText(
            "Enter hash here..."
        )

        self.hash_input.setMinimumHeight(
            45
        )

        # Press Enter to search
        self.hash_input.returnPressed.connect(
            self.check_hash
        )

        main.addWidget(
            self.hash_input
        )


        # ----------------------------------------------------
        # CHECK BUTTON
        # ----------------------------------------------------

        check_button = QPushButton(
            "CHECK HASH"
        )

        check_button.setMinimumHeight(
            50
        )

        check_button.clicked.connect(
            self.check_hash
        )

        main.addWidget(
            check_button
        )


        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        main.addWidget(
            QLabel("RESULT")
        )


        self.result = QLabel(
            "Waiting for hash..."
        )

        self.result.setWordWrap(
            True
        )

        self.result.setStyleSheet("""
            font-size: 19px;
            padding: 15px;
        """)

        main.addWidget(
            self.result
        )


        # ----------------------------------------------------
        # LOG
        # ----------------------------------------------------

        main.addWidget(
            QLabel("Activity Log")
        )


        self.log = QTextEdit()

        self.log.setReadOnly(
            True
        )

        main.addWidget(
            self.log
        )


        # ----------------------------------------------------
        # CLEAR
        # ----------------------------------------------------

        clear_button = QPushButton(
            "CLEAR"
        )

        clear_button.clicked.connect(
            self.clear_screen
        )

        main.addWidget(
            clear_button
        )


        self.setLayout(
            main
        )


    # ========================================================
    # DATABASE START (Optimized: Only builds if empty)
    # ========================================================

    def start_database(self):

        try:
            records = self.db.count()

            if records == 0:
                self.log.append(
                    "[+] Database is empty. Reading wordlist.txt..."
                )
                self.progress.setValue(0)

                build_database(
                    self.db,
                    self.update_progress
                )
                records = self.db.count()
                self.log.append(
                    "[+] Database ready."
                )
            else:
                self.log.append(
                    "[+] Loaded existing database successfully."
                )
                self.progress.setValue(100)

            self.database_status.setText(
                f"database.db | {records} hash records"
            )
            self.log.append(
                f"[+] Total records: {records}"
            )

        except Exception as error:

            self.database_status.setText(
                "Database ERROR"
            )

            self.log.append(
                f"[-] ERROR: {error}"
            )


    # ========================================================
    # PROGRESS
    # ========================================================

    def update_progress(self, value):

        self.progress.setValue(
            value
        )

        QApplication.processEvents()


    # ========================================================
    # REBUILD
    # ========================================================

    def rebuild_database(self):

        try:

            self.log.append(
                "[+] Rebuilding database..."
            )


            self.db.clear()


            self.progress.setValue(
                0
            )


            build_database(
                self.db,
                self.update_progress
            )


            records = self.db.count()


            self.database_status.setText(
                f"database.db | {records} hash records"
            )


            self.log.append(
                "[+] Database rebuilt successfully."
            )


        except Exception as error:

            QMessageBox.critical(
                self,
                "Database Error",
                str(error)
            )


    # ========================================================
    # CHECK HASH
    # ========================================================

    def check_hash(self):

        digest = (
            self.hash_input
            .text()
            .strip()
            .lower()
        )


        algorithm_name = (
            self.algorithm_box
            .currentText()
        )


        algorithm = ALGORITHMS[
            algorithm_name
        ]


        # ----------------------------------------------------
        # EMPTY
        # ----------------------------------------------------

        if not digest:

            self.result.setText(
                "RESULT: Please enter a hash."
            )

            return


        # ----------------------------------------------------
        # VALIDATE LENGTH
        # ----------------------------------------------------

        if len(digest) != HASH_LENGTHS[
            algorithm
        ]:

            self.result.setText(
                f"RESULT: INVALID {algorithm_name} HASH"
            )

            self.log.append(
                "[-] Invalid hash length."
            )

            return


        # ----------------------------------------------------
        # VALIDATE HEX
        # ----------------------------------------------------

        if any(
            character not in
            "0123456789abcdef"
            for character in digest
        ):

            self.result.setText(
                "RESULT: INVALID HASH FORMAT"
            )

            return


        self.log.append(
            f"[*] Searching {algorithm_name} database..."
        )


        # ----------------------------------------------------
        # DATABASE SEARCH
        # ----------------------------------------------------

        match = self.db.search(
            algorithm,
            digest
        )


        if match:

            plaintext = match[0]


            self.result.setText(
                "RESULT: MATCH FOUND\n\n"
                f"Algorithm: {algorithm_name}\n"
                f"Hash: {digest}\n"
                f"Plaintext: {plaintext}"
            )


            self.log.append(
                f"[+] MATCH FOUND → {plaintext}"
            )


        else:

            self.result.setText(
                "RESULT: NO MATCH IN LOCAL DATABASE"
            )


            self.log.append(
                "[-] No match found."
            )


    # ========================================================
    # CLEAR
    # ========================================================

    def clear_screen(self):

        self.hash_input.clear()

        self.result.setText(
            "Waiting for hash..."
        )

        self.log.clear()


    # ========================================================
    # CLOSE
    # ========================================================

    def closeEvent(self, event):

        self.db.close()

        event.accept()


# ============================================================
# MAIN
# ============================================================

def main():

    app = QApplication(
        sys.argv
    )

    window = HashCracker()

    window.show()

    sys.exit(
        app.exec()
    )


if __name__ == "__main__":

    main()
