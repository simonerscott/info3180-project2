import requests
from bs4 import BeautifulSoup
import urlparse

# url = "https://www.walmart.com/ip/54649026"
# result = requests.get(url)
# soup = BeautifulSoup(result.text, "html.parser")

def imgGet(url):
    #url = "https://www.walmart.com/ip/54649026"
    result = requests.get(url)
    soup = BeautifulSoup(result.text, "html.parser")

    
    imageLink = []
    # This will look for a meta tag with the og:image property
    og_image = (soup.find('meta', property='og:image') or
                        soup.find('meta', attrs={'name': 'og:image'}))
    if og_image and og_image['content']:
        pass
        # print og_image['content']
        # print ''
    
    # This will look for a link tag with a rel attribute set to 'image_src'
    thumbnail_spec = soup.find('link', rel='image_src')
    if thumbnail_spec and thumbnail_spec['href']:
        pass
        # print thumbnail_spec['href']
        # print ''
    
    # This will return image urls
    # for img in soup.findAll("img", src=True):
    #     urlparse.urljoin(url, img["src"])
    # return imageLink.append(urlparse.urljoin(url, img["src"]))
    
    for img in soup.findAll("img", src=True):
        imageLink.append(img["src"])
        
    return imageLink


    #return imageLink
#print imgGet()


# python -c 'from scrape import *; print imgGet()'