FROM python:3.7.8-slim

RUN mkdir -p /app
COPY index.py /app
WORKDIR /app

RUN apt-get update && apt-get install -y socat

# Set non root user
RUN useradd -c 'User' -m -d /home/user -s /bin/bash user
RUN chown -R user:user /home/user

USER user
ENV HOME /home/user

EXPOSE 3780
CMD ["socat", "TCP-LISTEN:3780,reuseaddr,fork", "EXEC:'python /app/index.py'"]
