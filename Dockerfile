# Use the official Ubuntu base image
FROM ubuntu:latest

# Set the environment variable to prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install necessary packages
RUN apt-get update && \
    apt-get install -y build-essential tcl wget git

# Clone the Redis source code from GitHub
RUN git clone https://github.com/redis/redis.git /usr/local/src/redis

# Set the working directory to the Redis source directory
WORKDIR /usr/local/src/redis

# Build Redis from source
RUN make && make install


# Copy the default Redis configuration file
RUN mkdir /etc/redis && cp /usr/local/src/redis/redis.conf /etc/redis/redis.conf

# Modify the configuration to allow connections from any IP address
RUN sed -i 's/^bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf
RUN sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf

# Expose Redis port
EXPOSE 6379

# Command to run Redis server
CMD ["redis-server", "/etc/redis/redis.conf"]