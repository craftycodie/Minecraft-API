from flask_mail import Mail, Message
from threading import Thread

def send_async_email(app, msg):
    mail = Mail(app)
    with app.app_context():
        try:
            mail.send(msg)
        except ConnectionRefusedError:
            raise EnvironmentError("[MAIL SERVER] not working")


def send_email(app, subject, sender, recipients, text_body):
    mail = Mail(app)
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    Thread(target=send_async_email, args=(app, msg)).start() 