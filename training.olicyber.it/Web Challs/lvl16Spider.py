import scrapy

class GFGSpider(scrapy.Spider):
    
    
    name = "gfg"
    
def start_requests(self):
    url_list = ["http://geeksforgeeks.org/careers/.../?"]
    for url in url_list:
        yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        page = response.url.split("/")[-2]
        filename = f"gfg-{page}.html"

        with open(filename, 'wb') as file:
            file.write(response.body)
        self.log(f'Saved file {filename}')