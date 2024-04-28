import tkinter as tk
from tkinter import messagebox
import scrapy
from scrapy.crawler import CrawlerRunner
from scrapy.utils.project import get_project_settings
from twisted.internet import reactor
import warnings
warnings.filterwarnings("ignore", category=scrapy.exceptions.ScrapyDeprecationWarning)


class QuotesSpider(scrapy.Spider):
    name = 'quotes'

    def parse(self, response):
        for quote in response.css('div.quote'):
            text = quote.css('span.text::text').get()
            author = quote.css('span small.author::text').get()
            yield {'text': text, 'author': author}

class BrowserSecurityToolApp:
    def __init__(self, master):
        self.master = master
        master.title("Browser Security Tool")

        self.label = tk.Label(master, text="Enter URL:")
        self.label.pack()

        self.url_entry = tk.Entry(master)
        self.url_entry.pack()

        self.scan_button = tk.Button(master, text="Scan", command=self.crawl_website)
        self.scan_button.pack()

        self.result_text = tk.Text(master)
        self.result_text.pack()

    def crawl_website(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "Please enter a URL.")
            return

        # Create a Scrapy runner
        runner = CrawlerRunner(get_project_settings())

        # Start the spider
        d = runner.crawl(QuotesSpider, start_urls=[url])
        d.addCallback(self.display_result)
        d.addBoth(lambda _: reactor.stop())  # Stop the reactor after the crawl is finished

        # Start the reactor if it's not already running
        if not reactor.running:
            reactor.run()

    def display_result(self, result):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Scraped Data:\n")
        for item in result:
            self.result_text.insert(tk.END, f"Text: {item['text']}, Author: {item['author']}\n")

def main():
    root = tk.Tk()
    app = BrowserSecurityToolApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
