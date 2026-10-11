import qrcode

qr = qrcode.make("This is just plain text, not a link")
qr.save("plaintext_test.png")