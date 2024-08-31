# Use the official Ubuntu base image
FROM ubuntu:latest

# Set the environment variable to prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED 1
# Update the package list and install necessary packages
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-dev \
    git \
    && apt-get clean

# Set the working directory to the Redis source directory
WORKDIR /usr/local/src/coolencryptmsg

COPY . /usr/local/src/coolencryptmsg
# Clone the Redis source code from GitHub
RUN pip3 install -r requirements.txt \
    && python3 manage.py migrate
# Expose port 8080
EXPOSE 8080

# Run the Django development server
CMD ["python3", "manage.py", "runserver", "0.0.0.0:8080"]

# Modify the configuration to allow connections from any IP address
# RUN sed -i 's/^bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf
# RUN sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf
