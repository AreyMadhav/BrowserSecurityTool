import requests
import tkinter as tk
from tkinter import messagebox
import webbrowser
import pyperclip
import time

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
        master.title("KNoxguard URL Scanner")

        self.label = tk.Label(master, text="Enter URL:")
        self.label.pack()

        self.url_entry = tk.Entry(master)
        self.url_entry.pack()

        self.scan_button = tk.Button(master, text="Scan", command=self.scan_url)
        self.scan_button.pack()

        self.result_text = tk.Text(master)
        self.result_text.pack()

        self.vt_scanner = VirusTotalScanner(api_key='14939d28a67da157e647fa5121adb7e52bd35cc7d05efd37dc49ad537dc4beb2')

        # Check clipboard for URL changes every 1 second
        self.master.after(1000, self.check_clipboard)

    def check_clipboard(self):
        clipboard_content = pyperclip.paste()
        if clipboard_content.startswith("http://") or clipboard_content.startswith("https://"):
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, clipboard_content)
            self.scan_url()
        self.master.after(1000, self.check_clipboard)

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
            harmless_engines = []
            harmful_engines = []
            for engine, res in result['scans'].items():
                if res['result'] == 'clean site' or res['result'] == 'unrated site':
                    harmless_engines.append((engine, res['result']))
                else:
                    harmful_engines.append((engine, res['result']))
            self.result_text.insert(tk.END, f"Harmless Engines ({len(harmless_engines)}):\n")
            self.result_text.insert(tk.END, f"\nHarmful Engines ({len(harmful_engines)}):\n")
            for engine, result in harmful_engines:
                self.result_text.insert(tk.END, f"{engine}: {result}\n")
        else:
            self.result_text.insert(tk.END, f"VirusTotal Scan Result: {result.get('verbose_msg', 'Unknown error')}\n")

def main():
    root = tk.Tk()
    app = VirusTotalScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
