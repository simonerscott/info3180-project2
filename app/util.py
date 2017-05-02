import smtplib


def sendemail(from_name, from_addr, to_name, to_addr, subject, msg):
    # from_name =  "My Name"
    # to_name = "Receiver's Name"
    # subject = "Lab 3 Exercise 1"
    # from_addr = "myemail@gmail.com"
    # to_addr = "receiveremail@somedomain.com"
    # msg = "This Excercise Is So Cool!!"
    message = """From: {} <{}>
To: {} <{}>
Subject: {}

{}
    
"""
    message_to_send = message.format(from_name, from_addr, to_name, to_addr, subject, msg)
    
    # Credentials (if needed)
    
    username = "myemail@gmail.com"
    password = "mysupersecretpassword"
    
    # The actual mail send
    
    server = smtplib.SMTP("smtp.gmail.com:587")
    server.starttls()
    server.login(username, password)
    server.sendmail(from_addr, to_addr, message_to_send)
    server.quit()