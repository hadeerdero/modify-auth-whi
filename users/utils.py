import os
from pytz import country_names
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import *
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from twilio.rest import Client
from django.utils.encoding import smart_str, smart_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text

frontEndDomain="http://170.187.154.46:8030/"
def sendEmail(data):
    message = Mail(
    from_email=Email("redfoxes.redfoxes@gmail.com"), 
    to_emails=To(data["to_email"]),
    subject=data["subject"],
    html_content=data["html_content"])
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
    except Exception as e:
        print(e)

def sendSMS(to,body,code=None):
    accountSid = os.environ.get('TWILIO_ACCOUNT_SID')
    authToken = os.environ.get('TWILIO_AUTH_TOKEN')
    client = Client(accountSid, authToken)
    message = body 
    if code :
        message += " Your Veridication code is " +str(code)
    message = client.messages.create(
                body=message,
                from_=os.environ.get('TWILIO_FROM_PHONE'),
                to=to,
            )

    print(message.sid)

def sentSMSVerificationCode(to,code):
    sendSMS(to=to,body="Verify your phone number at Health App .",code=code)

def sentSMSResetPasswordCode(to,code):
    sendSMS(to=to,body="to Reset Your Password use Veridication code .",code=code)



def sendVerifyEmail(request,user):
    tokens = RefreshToken.for_user(user)
    current_site = get_current_site(request).domain
    relative_link = reverse("verifyEmail")
    token =str(tokens.access_token)
    abs_url = f"http://{current_site}{relative_link}?token={token}"
    html_content = f'''
        <div> <h3>Verify Your Email ON Health App </h3></div>
        <div style="text-align: center;"> 
            <a href="{abs_url}" 
            style=" 
            background-color: #4CAF50;
            border: none;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;"> click to verify
            </a>
        </div>
        '''
    data = {
            "subject": "Verify Your Email On Health App. ",
            "to_email": user.email,
            "html_content": html_content
        }
    sendEmail(data)
    
def resetPasswordEmail(user):
    tokens = RefreshToken.for_user(user)
    uuid = urlsafe_base64_encode(smart_bytes(user.id))
    # token =str(tokens.access_token)
    token = PasswordResetTokenGenerator().make_token(user)
    abs_url = f"{frontEndDomain}find-account/reset-password?token={token}&uuid={uuid}"
    html_content = f'''
        <div> <h3>Reset Your Password On Health App </h3></div>
        <div style="text-align: center;"> 
            <a href="{abs_url}" 
            style=" 
            background-color: #4CAF50;
            border: none;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;">  Reset Passowrd
            </a>
        </div>
        '''
    data = {
            "subject": "Reset Your On Health App. ",
            "to_email": user.email,
            "html_content": html_content
        }
    sendEmail(data)