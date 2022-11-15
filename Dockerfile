FROM python:3.7-alpine
ENV SECRET_KEY='sztqfdq@!+-b4l8$@*#5=#w*s%p#43$)8q&(f-dz-v*#o$3#$b'
ENV SENDGRID_API_KEY='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'
ENV TWILIO_ACCOUNT_SID='AC2e6944c1cd0f878bd8340621b76a79d2'
ENV TWILIO_AUTH_TOKEN='8362ade93e3dffe2942d6019fe361add'
ENV TWILIO_FROM_PHONE='+18316042142'
ENV POSTGRES_DB=myproject
ENV POSTGRES_USER=myprojectuser
ENV POSTGRES_PASSWORD=password

ENV REDFOXES_SSH_PASSWORD=redf0xes
WORKDIR /public
COPY requirements.txt /public/

RUN pip install -r requirements.txt
RUN pip uninstall -y bson
RUN pip uninstall -y pymongo
RUN pip install pymongo==3.7.2 PyJWT==1.7.1
COPY . /public
EXPOSE 2271
