# Use the official Ubuntu base image
FROM ubuntu:20.04

# Set the environment variable to prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Set the working directory to the application directory
WORKDIR /usr/local/src/coolencryptmsg

# Copy the current directory contents into the container
COPY . .

# Install required packages
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    sqlite3 \
    libssl-dev \
    libffi-dev \
    libsodium-dev \  # Required for cryptography/bcrypt
    && apt-get clean

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Run migrations (important after installing requirements)
RUN python3 manage.py migrate

# Expose port 8080 for Django development server
EXPOSE 8080

# Run the Django development server
CMD ["python3", "manage.py", "runserver", "0.0.0.0:8080"]
