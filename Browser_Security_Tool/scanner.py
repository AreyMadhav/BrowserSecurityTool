import requests
import tkinter as tk
from tkinter import messagebox

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key

    def scan_url(self, url):
        params = {'apikey': self.api_key, 'resource': url, 'scan': 1, 'allinfo': 1}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        return response.json()

class VirusTotalScannerApp:
    def __init__(self, master):
        self.master = master
        master.title("VirusTotal URL Scanner")

        self.label = tk.Label(master, text="Enter URL:")
        self.label.pack()

        self.url_entry = tk.Entry(master)
        self.url_entry.pack()

        self.scan_button = tk.Button(master, text="Scan", command=self.scan_url)
        self.scan_button.pack()

        self.result_text = tk.Text(master)
        self.result_text.pack()

        self.vt_scanner = VirusTotalScanner(api_key='77d7872ee5d7deffe29d3d5f9a2860c82f621222c6531cff92636e8cbc1f9567')

    def scan_url(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "Please enter a URL.")
            return

        vt_result = self.vt_scanner.scan_url(url)
        self.display_result(vt_result)

    def display_result(self, result):
        self.result_text.delete(1.0, tk.END)
        if result.get('response_code') == 1:
            self.result_text.insert(tk.END, "VirusTotal Scan Result:\n")
            for key, value in result.items():
                self.result_text.insert(tk.END, f"{key}: {value}\n")
        else:
            self.result_text.insert(tk.END, f"Scan Result: {result.get('verbose_msg', 'Unknown error')}\n")

def main():
    root = tk.Tk()
    app = VirusTotalScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
