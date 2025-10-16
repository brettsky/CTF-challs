import qrcode
from PIL import Image

data = "77816@Dodo-Airlines"

img = qrcode.make(data)

img.save("qrcode.png")