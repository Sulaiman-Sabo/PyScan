# PyScan: AI-Powered Python Code Vulnerability Scanner

<div align="center">
  <img src="static/images/pyscan_logo.png" alt="PyScan Logo" width="150" height="150">
</div>

**PyScan** is a fast, AI-driven cybersecurity tool designed to automatically detect software vulnerabilities in Python source code. Built with a custom Deep Learning architecture (BiLSTM with Attention mechanism) in PyTorch, PyScan identifies 11 Common Weakness Enumeration (CWE) types directly at the function level.

It provides a modern, responsive Flask web interface that allows developers to drag-and-drop individual Python files, entire project folders, or `.zip` archives for instant, in-memory scanning.

---

## 🚀 Features

- **Deep Learning Detection:** Powered by a BiLSTM-Attention Neural Network trained on the CVEFixes dataset.
- **Function-Level Analysis:** Identifies the exact vulnerable function and predicts the associated CWE category.
- **Zero-Storage Privacy:** 100% privacy-first design. Your uploaded source code is processed entirely in RAM and is **never** saved to disk.
- **Modern Web Dashboard:** A sleek, dark-themed SaaS-like interface built with Flask, Bootstrap, and Chart.js.
- **User Authentication:** Secure role-based user authentication system with personal dashboards and scan history tracking.
- **Multiple Upload Modes:** Support for scanning single `.py` files, entire project folders, or compressed `.zip` archives (up to 1GB).

## 🛠️ Tech Stack

- **Backend:** Python, Flask, SQLAlchemy (SQLite)
- **Machine Learning:** PyTorch, NumPy, scikit-learn
- **Frontend:** HTML5, CSS3, JavaScript, Bootstrap 5, FontAwesome
- **Code Parsing:** Python `ast` (Abstract Syntax Trees), `tokenize`

## 📦 Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Sulaiman-Sabo/PyScan.git
   cd PyScan
   ```

2. **Create a Virtual Environment**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the Database & Run the App**
   ```bash
   python app.py
   ```
   The application will automatically create the database and start the local development server at `http://127.0.0.1:5000`.

## 🧠 Model Training (Optional)

If you wish to retrain the PyScan model from scratch:
1. Ensure the CVEFixes dataset is placed in the required directory.
2. Run the dataset processing script:
   ```bash
   python models/dataset.py
   ```
3. Run the training pipeline:
   ```bash
   python models/train_model.py
   ```
This will generate the calibrated PyTorch model weights and save the necessary tokenization vocabulary.

## 👨‍💻 Author

**Sulaiman Sabo**  
*BSc Cybersecurity Final Year Project*  
Federal University of Technology, Babura (FUTB)

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
